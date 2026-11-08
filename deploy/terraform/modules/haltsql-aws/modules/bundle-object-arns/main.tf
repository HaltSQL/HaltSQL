# Exact object ARNs a bundle_source.s3 reads: the bundle key and its detached
# signature, key.sig (lib/bundle_source/remote.ml GETs both). No wildcards.
# Kept free of providers so terraform test can check it without credentials.
locals {
  arns = flatten([
    for o in var.objects : [
      "arn:${var.partition}:s3:::${o.bucket}/${o.key}",
      "arn:${var.partition}:s3:::${o.bucket}/${o.key}.sig",
    ]
  ])
}
