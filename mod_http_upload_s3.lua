-- mod_http_upload_s3
--
-- Copyright (C) 2018 Abel Luck
-- Copyright (C) 2015-2016 Kim Alvefur
--
-- This file is MIT/X11 licensed.
--

-- imports
local st = require"util.stanza";
local uuid = require"util.uuid".generate;
local http = require "util.http";
local dataform = require "util.dataforms".new;
local HMAC = require "util.hashes".hmac_sha256;
local SHA256 = require "util.hashes".sha256;

-- config
local file_size_limit = module:get_option_number(module.name .. "_file_size_limit", 100 * 1024 * 1024); -- 100 MB
local aws_region = assert(module:get_option_string(module.name .. "_region"),
	module.name .. "_region is a required option");
local aws_bucket = assert(module:get_option_string(module.name .. "_bucket"),
	module.name .. "_bucket is a required option");
local aws_path = assert(module:get_option_string(module.name .. "_path"),
	module.name .. "_path is a required option");
local aws_access_id = assert(module:get_option_string(module.name .. "_access_id"),
	module.name .. "_aws_access_id is a required option");
local aws_secret_key = assert(module:get_option_string(module.name .. "_secret_key"),
	module.name .. "_aws_secret_key is a required option");
local aws_creds = {
	access_key = aws_access_id;
	secret_key = aws_secret_key;
}
local aws_service = "s3";


-- depends
module:depends("disco");

-- namespace
local legacy_namespace = "urn:xmpp:http:upload";
local namespace = "urn:xmpp:http:upload:0";

-- identity and feature advertising
module:add_identity("store", "file", module:get_option_string("name", "HTTP File Upload"))
module:add_feature(namespace);
module:add_feature(legacy_namespace);

module:add_extension(dataform {
	{ name = "FORM_TYPE", type = "hidden", value = namespace },
	{ name = "max-file-size", type = "text-single" },
}:form({ ["max-file-size"] = tostring(file_size_limit) }, "result"));

module:add_extension(dataform {
	{ name = "FORM_TYPE", type = "hidden", value = legacy_namespace },
	{ name = "max-file-size", type = "text-single" },
}:form({ ["max-file-size"] = tostring(file_size_limit) }, "result"));

local function sorted_iter(t)
	local i = {}
	for k in next, t do
		table.insert(i, k)
	end
	table.sort(i, function(a, b) return a > b end)
	return function()
		local k = table.remove(i)
		if k ~= nil then
			return k, t[k]
		end
	end
end

local function get_iso8601_basic(timestamp)
	return os.date("!%Y%m%dT%H%M%SZ", timestamp)
end

local function get_iso8601_basic_short(timestamp)
	return os.date("!%Y%m%d", timestamp)
end

local char_to_hex = function(c)
	return string.format("%%%02X", c:byte(1,1))
end

local function encode_uri_component(str)
	return (str:gsub("[^%w%-_%.%!%~%*%'%(%)]", char_to_hex))
end


local function hmac(key, value)
	return HMAC(key, value, false)
end

local function get_derived_signing_key(keys, timestamp, region, service)
	local date = get_iso8601_basic_short(timestamp)
	local k_secret = "AWS4" .. keys["secret_key"]
	return hmac(hmac(hmac(hmac(k_secret, date), region), service), "aws4_request")
end

local function get_cred_scope(timestamp, region, service)
	return get_iso8601_basic_short(timestamp)
		.. "/" .. region
		.. "/" .. service
		.. "/aws4_request"
end

local function get_signed_headers()
	return "content-length;content-type;host"
end

local function get_credential(keys, timestamp, region, service)
	return keys["access_key"] .. "/" .. get_cred_scope(timestamp, region, service)
end

local function get_canonical_query_string(timestamp, host, credential, request_method)
	local query_params = {
		["X-Amz-Acl"]           = "public-read";
		["X-Amz-Algorithm"]     = "AWS4-HMAC-SHA256";
		["X-Amz-Credential"]    = credential;
		["X-Amz-Date"]          = get_iso8601_basic(timestamp);
		["X-Amz-Expires"]       = "3600";
		["X-Amz-SignedHeaders"] = get_signed_headers();
	};

	if request_method == "PUT" then
		query_params["X-Amz-Content-Sha256"] = "UNSIGNED-PAYLOAD";
	end
	local qs_list = {};
	for param, value in sorted_iter(query_params) do
		encoded = encode_uri_component(param) .. "=" .. encode_uri_component(value)
		table.insert(qs_list, encoded)
	end
	return table.concat(qs_list, "&")
end

local function get_hashed_canonical_request(timestamp, host, uri, request_method, credential, size, mime)
	local unsigned_payload = "UNSIGNED-PAYLOAD"
	local canonical_query_string = get_canonical_query_string(timestamp, host, credential, request_method)
	local canonical_request = request_method .. "\n"
		.. uri .. "\n"
		.. canonical_query_string .. "\n"
		.. "content-length:" .. size .."\n"
		.. "content-type:" .. mime .."\n"
		.. "host:" .. host .. "\n"
		.. "\n"
		.. get_signed_headers() .. "\n"
		.. unsigned_payload
	return SHA256(canonical_request, true)
end

local function get_string_to_sign(timestamp, region, service, host, uri, request_method, credential, size, mime)
	return "AWS4-HMAC-SHA256\n"
		.. get_iso8601_basic(timestamp) .. "\n"
		.. get_cred_scope(timestamp, region, service) .. "\n"
		.. get_hashed_canonical_request(timestamp, host, uri, request_method, credential, size, mime)
end

local function get_signature(derived_signing_key, string_to_sign)
	return HMAC(derived_signing_key, string_to_sign, true)
end

local function build_uri(host, uri, query_string)
	local url = string.format("https://%s%s", host, uri)
	if query_string ~= nil then
		url = url .. "?" .. query_string
	end
	return url
end

local function build_signed_url(keys, timestamp, region, service, host, uri, request_method, size, mime)
	-- we are using AWS Signature V 4 with query parameters instead of headers
	-- ref: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
	local derived_signing_key = get_derived_signing_key(keys, timestamp, region, service)
	local credential          = get_credential(keys, timestamp, region, service)
	local string_to_sign      = get_string_to_sign(timestamp, region, service, host, uri, request_method, credential, size, mime)
	local signature           = get_signature(derived_signing_key, string_to_sign)
	local query_string        = get_canonical_query_string(timestamp, host, credential, request_method)
	local signed_query_string = query_string .. "&X-Amz-Signature=" .. signature
	local url                 = build_uri(host, uri, signed_query_string)
	return url
end

local function build_host(service, region)
	return string.format("%s-%s.amazonaws.com", service, region)
end

local function get_public_get(service, region, uri)
	local timestamp = tonumber(os.time())
	local host      = build_host(service, region)
	local url       = build_uri(host, uri, nil)
	return url
end

local function get_presigned_put(credentials, service, region, uri, size, mime)
	local timestamp = tonumber(os.time())
	local host      = build_host(service, region)
	local url       = build_signed_url(credentials, timestamp, region, service, host, uri, "PUT", size, mime)
	return url
end

local function handle_request(origin, stanza, xmlns, filename, filesize, filetype)
	-- local clients only
	if origin.type ~= "c2s" then
		module:log("debug", "Request for upload slot from a %s", origin.type);
		origin.send(st.error_reply(stanza, "cancel", "not-authorized"));
		return nil, nil;
	end
	-- validate
	if not filename or filename:find("/") then
		module:log("debug", "Filename %q not allowed", filename or "");
		origin.send(st.error_reply(stanza, "modify", "bad-request", "Invalid filename"));
		return nil, nil;
	end
	if not filesize then
		module:log("debug", "Missing file size");
		origin.send(st.error_reply(stanza, "modify", "bad-request", "Missing or invalid file size"));
		return nil, nil;
	elseif filesize > file_size_limit then
		module:log("debug", "File too large (%d > %d)", filesize, file_size_limit);
		origin.send(st.error_reply(stanza, "modify", "not-acceptable", "File too large",
			st.stanza("file-too-large", {xmlns=xmlns})
				:tag("max-size"):text(tostring(file_size_limit))));
		return nil, nil;
	end

	local random  = http.urlencode(uuid());
	filename      = http.urlencode(filename)
	local uri     = string.format("/%s/%s/%s-%s", aws_bucket, aws_path, random, filename);
	module:log("debug", "slot request %s %s", filesize, filetype);
	local put_url = get_presigned_put(aws_creds, aws_service, aws_region, uri, filesize, filetype);
	local get_url = get_public_get(aws_service, aws_region, uri);

	module:log("debug", "Handing out upload slot GET %s PUT %s to %s@%s [%d %s]", get_url, put_url, origin.username, origin.host, filesize, filetype);

	return get_url, put_url;
end

-- hooks
module:hook("iq/host/"..legacy_namespace..":request", function (event)
	local stanza, origin = event.stanza, event.origin;
	local request        = stanza.tags[1];
	local filename       = request:get_child_text("filename");
	local filesize       = tonumber(request:get_child_text("size"));
	local filetype       = request:get_child_text("content-type") or "application/octet-stream";

	local get_url, put_url = handle_request(
		origin, stanza, legacy_namespace, filename, filesize, filetype);

	if not get_url then
		-- error was already sent
		return true;
	end

	local reply = st.reply(stanza)
		:tag("slot", { xmlns = legacy_namespace })
			:tag("get"):text(get_url):up()
			:tag("put"):text(put_url):up()
		:up();
	origin.send(reply);
	return true;
end);

module:hook("iq/host/"..namespace..":request", function (event)
	local stanza, origin = event.stanza, event.origin;
	local request        = stanza.tags[1];
	local filename       = request.attr.filename;
	local filesize       = tonumber(request.attr.size);
	local filetype       = request.attr["content-type"] or "application/octet-stream";

	local get_url, put_url = handle_request(
		origin, stanza, namespace, filename, filesize, filetype);

	if not get_url then
		-- error was already sent
		return true;
	end

	local reply = st.reply(stanza)
		:tag("slot", { xmlns = namespace})
			:tag("get", { url = get_url }):up()
			:tag("put", { url = put_url }):up()
		:up();
	origin.send(reply);
	return true;
end);
