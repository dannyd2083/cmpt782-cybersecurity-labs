resource "aws_instance" "public_instance" {
  ami                         = aws_ami_copy.ubuntu_copy.id  # Use the AMI from Task 5
  instance_type               = "t2.micro"                   # Free tier eligible instance type
  subnet_id                   = aws_subnet.public.id         # Public subnet ID
  associate_public_ip_address = true                         # Assign a public IP for SSH and internet access
  key_name                    = "CYBERSECURITY_EC2_PUB"      # Use the key pair created in AWS
  
  security_groups = [
    aws_security_group.allow_ssh.id,       # Allow SSH access
    aws_security_group.allow_tcp_8081.id,  # Allow access to port 8081
    aws_security_group.allow_all_outgoing.id  # Allow all outgoing traffic
  ]

  tags = {
    Name = "Public_Instance"
  }
}

resource "aws_instance" "private_instance" {
  ami                         = aws_ami_copy.ubuntu_copy.id  # Use the AMI from Task 5
  instance_type               = "t2.micro"                  # Free-tier eligible
  subnet_id                   = aws_subnet.private.id       # Private subnet from Task 1
  associate_public_ip_address = false                       # No public IP in private subnet
  key_name                    = "CYBERSECURITY_EC2_PUB"     # Key pair for SSH access

  vpc_security_group_ids = [
    aws_security_group.allow_ssh.id,          # Allow inbound SSH
    aws_security_group.allow_all_outgoing.id  # Allow all outbound traffic
  ]

  tags = {
    Name = "Private_Instance"
  }
}
