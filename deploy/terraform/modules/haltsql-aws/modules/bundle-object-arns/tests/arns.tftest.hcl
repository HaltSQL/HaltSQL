# Regression: the task role allowed s3:GetObject on the bundle key only, so the
# signature GET (key.sig) was denied and every S3 bundle_source failed.

run "bundle_and_signature" {
  command = plan

  variables {
    partition = "aws"
    objects = [
      { bucket = "bundles", key = "prod/policy.haltsqlbundle" },
      { bucket = "other", key = "b" },
    ]
  }

  assert {
    condition = output.arns == [
      "arn:aws:s3:::bundles/prod/policy.haltsqlbundle",
      "arn:aws:s3:::bundles/prod/policy.haltsqlbundle.sig",
      "arn:aws:s3:::other/b",
      "arn:aws:s3:::other/b.sig",
    ]
    error_message = "each bundle object needs exactly its key and key.sig"
  }
}

run "no_objects" {
  command = plan

  variables {
    partition = "aws-cn"
    objects   = []
  }

  assert {
    condition     = length(output.arns) == 0
    error_message = "no objects, no ARNs"
  }
}
