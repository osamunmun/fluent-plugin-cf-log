[![Build Status](https://travis-ci.org/osamunmun/fluent-plugin-cf-log.svg?branch=master)](https://travis-ci.org/osamunmun/fluent-plugin-cf-log)


# Fluent::Plugin::Cf::Log

Welcome to your new gem! In this directory, you'll find the files you need to be able to package up your Ruby library into a gem. Put your Ruby code in the file `lib/fluent/plugin/cf/log`. To experiment with that code, run `bin/console` for an interactive prompt.

TODO: Delete this and the text above, and describe your gem

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'fluent-plugin-cf-log'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install fluent-plugin-cf-log

## Usage

ex: config

```
<source>
  @type cf_log
  @id cf_log_input

  region             ap-northeast-1
  s3_bucketname      something.bucket.com
  s3_prefix          cloudfront-logs
  tag                cf.access
  timestamp_file     /tmp/fluentd/cf_last_at
  access_key_id      XXXXXXXXXXXXXXXXXXXX
  secret_access_key  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  refresh_interval   10
</source>
```

ex: output

```
2016-02-26 18:23:17 +0900 debug.cf.access: {"key":"cloudfront-logs/E1J6F82H8ACXN4.2016-01-30-03.36ee1adc","prefix":"cloudfront-logs","distribution_id":"ZZZZZZZZZ","logfile_date":"2016-01-30-03","unique_id":"36ee1adc","cf_timestamp_unixtime":1456467464,"datetime":"2016-01-30\t03:59:53","x_edge_location":"NRT53","sc_bytes":"357","c_ip":"xxx.xxx.xxx.xxx","cs_method":"GET","cs_host":0.0,"cs_uri_stem":"/foo.jpg","sc_status":"304","cs_referer":"http://example.com/","cs_ua":"Mozilla/5.0%2520(Windows%2520NT%25206.3;%2520WOW64;%2520Trident/7.0;%2520rv:11.0)%2520like%2520Gecko","cs_uri_query":"size=33","cs_cookie":"-","x_edge_result_type":"Miss","x_edge_request_id":"xxxxxx","x_host_header":"example.com","cs_protocol":"https","cs_bytes":"569","time_taken":"0.568","x_forwarded_for":"-","ssl_protocol":"TLSv1.2","ssl_cipher":"ECDHE-RSA-AES128-SHA256","x_edge_response_result_type":"Miss"}
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/osamunmun/fluent-plugin-cf-log. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](contributor-covenant.org) code of conduct.

