module Fluent
  class CfLogInput < Input
    Fluent::Plugin.register_input('cf_log', self)

    LOGFILE_REGEXP = /^((?<prefix>.+?)\/|)\/(?<distribution_id>.+?)\.(?<logfile_date>[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2})\.(?<unique_id>.+)\.gz$/
    ACCESSLOG_REGEXP = /^(?<date>\d{4}-\d{2}-\d{2})\t(?<time>\d{2}\:\d{2}\:\d{2}) (?<x_edge_location>.+?) (?<client>[^ ]+) (?<sc_bytes>.+?) (?<c_ip>.+?) (?<cs_method>.+?) (?<cs_host>.+?) (?<cs_uri_stem>.+?) (?<sc_status>.+?) (?<cs_referer>.+?) (?<cs_ua>.+?) (?<cs_uri_query>.+?) (?<cs_cookie>.+?) (?<x_edge_result_type>.+?) (?<x_edge_request_id>.+?) (?<x_host_header>.+?) (?<cs_protocol>.*?) (?<cs_bytes>.+?) (?<time_taken>.+) (?<x_forwarded_for>.+?) (?<ssl_protocol>.+?) (?<ssl_cipher>.+?) (?<x_edge_response_result_type>.+?)$/


    config_param :access_key_id, :string, default: nil, secret: true
    config_param :secret_access_key, :string, default: nil, secret: true
    config_param :region, :string, default: nil
    config_param :s3_bucketname, :string, default: nil
    config_param :s3_prefix, :string, default: nil
    config_param :tag, :string, default: 'cf.access'
    config_param :timestamp_file, :string, default: nil
    config_param :refresh_interval, :integer, default: 300
    config_param :buf_file, :string, default: './fluentd_elb_log_buf_file'
    config_param :proxy_uri, :string, default: nil

    def configure(conf)
      super
      require 'aws-sdk'
      raise Fluent::ConfigError.new("region is required") unless @region
      if !has_iam_role?
        raise Fluent::ConfigError.new("access_key_id is required") if @access_key_id.nil?
        raise Fluent::ConfigError.new("secret_access_key is required") if @secret_access_key.nil?
      end
      raise Fluent::ConfigError.new("s3_bucketname is required") unless @s3_bucketname
      raise Fluent::ConfigError.new("timestamp_file is required") unless @timestamp_file
    end

    def start
      super

      File.open(@timestamp_file, File::RDWR|File::CREAT).close
      File.open(@buf_file, File::RDWR|File::CREAT).close

      raise StandardError.new("s3 bucket not found #{@s3_bucketname}") unless s3bucket_is_ok()

      @loop = Coolio::Loop.new
      timer_trigger = TimerWatcher.new(@refresh_interval, true, &method(:input))
      timer_trigger.attach(@loop)
      @thread = Thread.new(&method(:run))
    end

    def shutdown
      super
      @loop.stop
      @thread.join
    end

    def has_iam_role?
      begin
        ec2 = Aws::EC2::Client.new(region: @region)
        !ec2.config.credentials.nil?
      rescue => e
        $log.warn "EC2 Client error occurred: #{e.message}"
      end
    end

    def get_timestamp_file
      begin
        timestamp = 0
        $log.debug "timestamp file #{@timestamp_file} read"
        File.open(@timestamp_file, File::RDONLY) do |file|
          timestamp = file.read.to_i
        end
        $log.debug "timestamp start at:" + Time.at(timestamp).to_s
        return timestamp
      rescue => e
        $log.warn "timestamp file get and parse error occurred: #{e.message}"
      end
    end

    def put_timestamp_file(timestamp)
      begin
        $log.debug "timestamp file #{@timestamp_file} write"
        File.open(@timestamp_file, File::WRONLY|File::CREAT|File::TRUNC) do |file|
          file.puts timestamp.to_s
        end
      rescue => e
        $log.warn "timestamp file get and parse error occurred: #{e.message}"
      end
    end

    def s3_client
      begin
        options = {
          :region => @region,
        }
        if @access_key_id && @secret_access_key
          options[:access_key_id] = @access_key_id
          options[:secret_access_key] = @secret_access_key
        end
        $log.debug "S3 client connect"
        Aws::S3::Client.new(options)
      rescue => e
        $log.warn "S3 Client error occurred: #{e.message}"
      end
    end

    def s3bucket_is_ok
      begin
        $log.debug "search bucket #{@s3_bucketname}"

        s3_client.list_buckets.buckets.any? do |bucket|
          bucket.name == @s3_bucketname
        end
      rescue => e
        $log.warn "S3 Client error occurred: #{e.message}"
      end
    end

    def input
      $log.debug "start"

      timestamp = get_timestamp_file()

      object_keys = get_object_keys(timestamp)
      object_keys = sort_object_key(object_keys)

      $log.info "processing #{object_keys.count} object(s)."

      object_keys.each do |object_key|
        record_common = {
          "account_id" => object_key[:account_id],
          "region" => object_key[:region],
          "logfile_date" => object_key[:logfile_date],
          "logfile_elb_name" => object_key[:logfile_elb_name],
          "elb_ip_address" => object_key[:elb_ip_address],
          "logfile_hash" => object_key[:logfile_hash],
          "elb_timestamp" => object_key[:elb_timestamp],
          "key" => object_key[:key],
          "prefix" => object_key[:prefix],
          "elb_timestamp_unixtime" => object_key[:elb_timestamp_unixtime],
        }

        get_file_from_s3(object_key[:key])
        emit_lines_from_buffer_file(record_common)

        put_timestamp_file(object_key[:elb_timestamp_unixtime])
      end
    end

    def get_object_keys(timestamp)
      begin
        object_keys = []

        objects = s3_client.list_objects(
          bucket: @s3_bucketname,
          max_keys: 100,
          prefix: @s3_prefix,
        )

        objects.each do |object|
          object.contents.each do |content|
            matches = LOGFILE_REGEXP.match(content.key)
            next unless matches
            cf_timestamp_unixtime = Time.parse(matches[:elb_timestamp]).to_i
            next if cf_timestamp_unixtime <= timestamp

            $log.debug content.key
            object_keys << {
              key: content.key,
              prefix: matches[:prefix],
              distribution_id: matches[:distribution_id],
              logfile_date: matches[:logfile_date],
              unique_id: matches[:unique_id],
              cf_timestamp_unixtime: cf_timestamp_unixtime,
            }
          end
        end
        return object_keys
      rescue => e
        $log.warn "error occurred: #{e.message}"
      end
    end

    def sort_object_key(src_object_keys)
      begin
        src_object_keys.sort do |a, b|
          a[:cf_timestamp_unixtime] <=> b[:cf_timestamp_unixtime]
        end
      rescue => e
        $log.warn "error occurred: #{e.message}"
      end
    end

    def get_file_from_s3(object_name)
      begin
        $log.debug "getting object from s3 name is #{object_name}"
        File.open(@buf_file, File::WRONLY|File::CREAT|File::TRUNC) do |file|
          s3_client.get_object(
            bucket: @s3_bucketname,
            key: object_name
          ) do |chunk|
            file.write(chunk)
          end
        end
      rescue => e
        $log.warn "error occurred: #{e.message}"
      end
    end

    def emit_lines_from_buffer_file(record_common)
      begin
        File.open(@buf_file, File::RDONLY) do |file|
          file.each_line do |line|
            line_match = ACCESSLOG_REGEXP.match(line)
            unless line_match
              $log.info "nomatch log found: #{line} in #{record_common['key']}"
              next
            end

            record = {
              "date" => line_match[:date],
              "time" => line_match[:time],
              "x_edge_location" => line_match[:x_edge_location],
              "sc_bytes" => line_match[:sc_bytes],
              "c_ip" => line_match[:c_ip],
              "cs_method" => line_match[:cs_method],
              "cs_host" => line_match[:cs_host].to_f,
              "cs_uri_stem" => line_match[:cs_uri_stem],
              "sc_status" => line_match[:sc_status],
              "cs_referer" => line_match[:cs_referer],
              "cs_user_agent" => line_match[:cs_user_agent],
              "cs_uri_query" => line_match[:cs_uri_query],
              "cs_cookie" => line_match[:cs_cookie],
              "x_edge_result_type" => line_match[:x_edge_result_type],
              "x_edge_request_id" => line_match[:x_edge_request_id],
              "x_host_header" => line_match[:x_host_header],
              "cs_protocol" => line_match[:cs_protocol],
              "cs_bytes" => line_match[:cs_bytes],
              "time_taken" => line_match[:time_taken],
              "x_forwarded_for" => line_match[:x_forwarded_for],
              "ssl_protocol" => line_match[:ssl_protocol],
              "ssl_cipher" => line_match[:ssl_cipher],
              "x_edge_response_result_type" => line_match[:x_edge_response_result_type]
            }

            router.emit(@tag, Fluent::Engine.now, record_common.merge(record))
          end
        end
      rescue => e
        $log.warn "error occurred: #{e.message}"
      end
    end

    def run
      @loop.run
    end

    class TimerWatcher < Coolio::TimerWatcher
      def initialize(interval, repeat, &callback)
        @callback = callback
        on_timer # first call
        super(interval, repeat)
      end

      def on_timer
        @callback.call
      end
    end
  end
end
