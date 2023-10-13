This is a temporary until s3fs and dependencies support urllib3 v2.0.

In theory, this shoul dbe file by the time this commit in merged and a package is released: https://github.com/fsspec/s3fs/issues/801

Once available, we can merge that script in the archiver script and have it handled transparently.
