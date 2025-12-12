resource "aws_eip" "nat_eip" {
  domain = "vpc"

  tags = {
    Name = "NAT_EIP"
  }
}

resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public.id

  tags = {
    Name = "CYBERSECURITY_NAT_GATEWAY"
  }
}
