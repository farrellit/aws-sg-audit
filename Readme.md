
You might invoke something like this to find open ports in which you are interested
For example, to check anything in sg `sg-e5225139` having access to ports either `3306` or `22`, try something like:

<pre>
aws ec2 describe-security-groups | ruby ./aws-sg-audit.rb  -p 3306 -p 22 -g sg-e5225139
</pre>

Output is in JSON.  You can also provide a JSON input file if you wish.

See `ruby ./aws-sg-audit.rb --help` for full usage ( note -filters are ORd together )
