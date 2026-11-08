variable "partition" {
  description = "AWS partition of the ARNs (aws, aws-cn, aws-us-gov)."
  type        = string
}

variable "objects" {
  description = "S3 objects holding signed policy bundles (bundle_source.s3): exact bucket and key."
  type = list(object({
    bucket = string
    key    = string
  }))
}
