---
description: HTTP File Upload (Amazon AWS S3)
labels: 'Stage-Alpha'
---

Introduction
============

This module implements [XEP-0363](https://xmpp.org/extensions/xep-0363.html),
which lets clients upload files over HTTP directly to an Amazon AWS S3 bucket.
No extra server-side code is required.

This module generates URLs that are signed using [AWS Signature Version
4](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html)
to upload to S3. To download/GET files, the S3 bucket must be made public. A
random UUID is used in the URL for each uploaded file to prevent filename
collisions.

S3 Configuration
================

1. Choose an AWS region to store your files, note the region id
   for this example we choose `eu-west-2`
2. Create the bucket in [the S3 console](https://s3.console.aws.amazon.com/s3/buckets/)
   for this example we choose `the_best_bucket`
3. Choose a path inside the root of the bucket uploads should land in
   for this example we choose `http_uploads`
4. Create a Bucket Policy (Bucket > Permissions > Bucket Policy) that marks all objects in this path as public:
```{.json}
{
  "Id": "Policy153727464300",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt153727464300",
      "Action": [
        "s3:GetObject"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::the_best_bucket/http_uploads/*",
      "Principal": "*"
    }
  ]
}
```


Prosody Configuration
=====================

Add `"http_upload_s3"` to `modules_enabled` in your global section, or under the host(s) you wish
to use it on.

``` {.lua}

--  Your AWS access key id
http_upload_s3_access_id = "AKTESTKEY";

--  Your AWS secret access key
http_upload_s3_secret_key = "YUNOCHANGEDMEKEY";

-- The region your bucket is located in
http_upload_s3_region = "eu-west-2";

-- The full name of your bucket
http_upload_s3_bucket = "the_best_bucket";

-- The directory under the bucket root to store files in
http_upload_s3_path  = "http_uploads";

-- A maximum file size can be set by:
--  default: 100MB (100\*1024\*1024)
http_upload_s3_file_size_limit = 123 -- bytes
```


Compatibility
=============

Works with Prosody 0.10.x and later.

