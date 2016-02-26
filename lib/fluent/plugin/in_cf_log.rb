module Fluent
  class CfLogInput < Input
    Fluent::Plugin.register_input('cf_log', self)
    unless method_defined?(:router)
      define_method("router") { Fluent::Engine }
    end

    LOGFILE_REGEXP = /^((?<prefix>.+?)\/|)(?<distribution_id>.+?)\.(?<logfile_date>[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2})\.(?<unique_id>.+)$/
    ACCESSLOG_REGEXP = /^(?<datetime>\d{4}-\d{2}-\d{2}\t\d{2}\:\d{2}\:\d{2})\t(?<x_edge_location>.+?)\t(?<sc_bytes>.+?)\t(?<c_ip>.+?)\t(?<cs_method>.+?)\t(?<cs_host>.+?)\t(?<cs_uri_stem>.+?)\t(?<sc_status>.+?)\t(?<cs_referer>.+?)\t(?<cs_ua>.+?)\t(?<cs_uri_query>.+?)\t(?<cs_cookie>.+?)\t(?<x_edge_result_type>.+?)\t(?<x_edge_request_id>.+?)\t(?<x_host_header>.+?)\t(?<cs_protocol>.*?)\t(?<cs_bytes>.+?)\t(?<time_taken>.+)\t(?<x_forwarded_for>.+?)\t(?<ssl_protocol>.+?)\t(?<ssl_cipher>.+?)\t(?<x_edge_response_result_type>.+?)$/


    config_param :access_key_id, :string, default: nil, secret: true
    config_param :secret_access_key, :string, default: nil, secret: true
    config_param :region, :string, default: nil
    config_param :s3_bucketname, :string, default: nil
    config_param :s3_prefix, :string, default: nil
    config_param :tag, :string, default: 'cf.access'
    config_param :timestamp_file, :string, default: nil
    config_param :refresh_interval, :integer, default: 300
    config_param :buf_file, :string, default: './fluentd_cf_log_buf_file'
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

      raise StandardError.new("s3 bucket not found #{@s3_bucketname}") unless s3bucket_is_ok()

      @loop = Coolio::Loop.new
      timer_trigger = TimerWatcher.new(@refresh_interval, true, &method(:fetch))
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

    def fetch
      $log.debug "start"

      timestamp = get_timestamp_file()
      object_keys = get_object_keys(timestamp)

      $log.info "processing #{object_keys.count} object(s)."

      object_keys.each do |object_key|
        record_common = {
          key: object_key[:key],
          prefix: object_key[:prefix],
          distribution_id: object_key[:distribution_id],
          logfile_date: object_key[:logfile_date],
          unique_id: object_key[:unique_id],
          cf_timestamp_unixtime: object_key[:cf_timestamp_unixtime],
        }

        object_name = object_key[:key]
        $log.debug "getting object from s3 name is #{object_name}"
        access_log = s3_client.get_object(
          bucket: @s3_bucketname,
          key: object_name
        ).body.string
        emit_log(access_log, record_common)
        put_timestamp_file(object_key[:cf_timestamp_unixtime])
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
            cf_timestamp_unixtime = content.last_modified.to_i
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

    def emit_log(access_log, record_common)
      begin
        access_log.split("\n").each do |line|
          line_match = ACCESSLOG_REGEXP.match(line)
          unless line_match
            $log.info "nomatch log found: #{line} in #{record_common['key']}"
            next
          end

          record = {
            datetime: line_match[:datetime],
            x_edge_location: line_match[:x_edge_location],
            sc_bytes: line_match[:sc_bytes],
            c_ip: line_match[:c_ip],
            cs_method: line_match[:cs_method],
            cs_host: line_match[:cs_host].to_f,
            cs_uri_stem: line_match[:cs_uri_stem],
            sc_status: line_match[:sc_status],
            cs_referer: line_match[:cs_referer],
            cs_ua: line_match[:cs_ua],
            cs_uri_query: line_match[:cs_uri_query],
            cs_cookie: line_match[:cs_cookie],
            x_edge_result_type: line_match[:x_edge_result_type],
            x_edge_request_id: line_match[:x_edge_request_id],
            x_host_header: line_match[:x_host_header],
            cs_protocol: line_match[:cs_protocol],
            cs_bytes: line_match[:cs_bytes],
            time_taken: line_match[:time_taken],
            x_forwarded_for: line_match[:x_forwarded_for],
            ssl_protocol: line_match[:ssl_protocol],
            ssl_cipher: line_match[:ssl_cipher],
            x_edge_response_result_type: line_match[:x_edge_response_result_type]
          }

          router.emit(@tag, Fluent::Engine.now, record_common.merge(record))
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
