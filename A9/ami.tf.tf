data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"]
}

resource "aws_ami_copy" "ubuntu_copy" {
  source_ami_id        = data.aws_ami.ubuntu.id
  source_ami_region    = "us-east-1"
  name                 = "Copied_Ubuntu_18.04_AMI"
  description          = "A copy of Ubuntu 18.04 AMD64 AMI"

  tags = {
    Name = "Copied_Ubuntu_18.04"
  }
}
