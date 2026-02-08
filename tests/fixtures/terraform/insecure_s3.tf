# Insecure S3 bucket — multiple security issues
resource "aws_s3_bucket" "insecure_data" {
  bucket = "my-insecure-data-bucket"
  acl    = "public-read"

  # No encryption
  # No versioning
  # No logging
  # No lifecycle rules
}

# No public access block resource exists

# Bucket policy without SSL enforcement
resource "aws_s3_bucket_policy" "insecure_policy" {
  bucket = aws_s3_bucket.insecure_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.insecure_data.arn}/*"
      }
    ]
  })
}
