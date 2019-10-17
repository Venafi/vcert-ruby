# vcert-ruby
!!!!This is work in progress!!!!

To test make credentials file with following variables:
```bash
export TPPUSER='admin'
export TPPPASSWORD='xxxxxx'
export TPPURL="https://ha-tpp.example.com/vedsdk"
export TPPZONE="devops\\\\vcert"
export CLOUDAPIKEY='xxxxxx-xxxx-xxxx-xxxxx-xxxxxxxxx'
CLOUDURL='https://api.dev01.qa.venafi.io/v1'
export CLOUDZONE=Default
```

Then run example scripts with following command:
```bash
source credentials
ruby -Ilib examples/get_cert.rb
```