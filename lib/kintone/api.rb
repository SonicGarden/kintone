require 'faraday'
require 'faraday_middleware'
require 'base64'
require 'json'
require 'kintone/command/accessor'
require 'kintone/api/guest'
require 'kintone/query'
require 'kintone/kintone_error'

class Kintone::Api
  BASE_PATH = '/k/v1/'.freeze
  COMMAND = '%s.json'.freeze
  ACCESSIBLE_COMMAND = [
    :record, :records, :form, :app_acl, :record_acl,
    :field_acl, :template_space, :space, :space_body, :space_thread,
    :space_members, :guests, :app, :apps, :apis,
    :bulk_request, :bulk, :file, :preview_form
  ].freeze

  # 次のいずれかでコンストラクト
  # domain, user
  # domain, user, password
  # domain, user, password, { basic_user, basic_password }
  # domain, user, { password, basic_user, basic_password }
  def initialize(domain, user, *rest_args)
    password, basic_user, basic_password = parse_initial_args(rest_args)
    @connection =
      Faraday.new(url: "https://#{domain}", headers: build_headers(user, password)) do |builder|
        builder.use Faraday::Request::BasicAuthentication, basic_user, basic_password if basic_user && basic_password
        builder.request :url_encoded
        builder.request :multipart
        builder.response :json, content_type: /\bjson$/
        builder.adapter :net_http
      end

    yield(@connection) if block_given?
  end

  def get_url(command)
    BASE_PATH + (COMMAND % command)
  end

  def guest(space_id)
    Kintone::Api::Guest.new(space_id, self)
  end

  def get(url, params = {})
    response =
      @connection.get do |request|
        request.url url
        # NOTE: Request URI Too Large 対策
        request.headers['Content-Type'] = 'application/json'
        request.body = params.to_h.to_json
      end
    raise Kintone::KintoneError.new(response.body, response.status) if response.status != 200
    response.body
  end

  def post(url, body)
    response =
      @connection.post do |request|
        request.url url
        request.headers['Content-Type'] = 'application/json'
        request.body = body.to_json
      end
    raise Kintone::KintoneError.new(response.body, response.status) if response.status != 200
    response.body
  end

  def put(url, body)
    response =
      @connection.put do |request|
        request.url url
        request.headers['Content-Type'] = 'application/json'
        request.body = body.to_json
      end
    raise Kintone::KintoneError.new(response.body, response.status) if response.status != 200
    response.body
  end

  def delete(url, body = nil)
    response =
      @connection.delete do |request|
        request.url url
        request.headers['Content-Type'] = 'application/json'
        request.body = body.to_json
      end
    raise Kintone::KintoneError.new(response.body, response.status) if response.status != 200
    response.body
  end

  def post_file(url, path, content_type, original_filename)
    response =
      @connection.post do |request|
        request.url url
        request.headers['Content-Type'] = 'multipart/form-data'
        request.body = { file: Faraday::UploadIO.new(path, content_type, original_filename) }
      end
    raise Kintone::KintoneError.new(response.body, response.status) if response.status != 200
    response.body['fileKey']
  end

  def method_missing(name, *args)
    if ACCESSIBLE_COMMAND.include?(name)
      CommandAccessor.send(name, self)
    else
      super
    end
  end

  def respond_to_missing?(name, *args)
    ACCESSIBLE_COMMAND.include?(name) || super
  end

  def update_headers(headers)
    @connection.headers.update(headers)
  end

  class CommandAccessor
    extend Kintone::Command::Accessor
  end

  private

  def build_headers(user, password)
    if password # パスワード認証
      { 'X-Cybozu-Authorization' => Base64.strict_encode64("#{user}:#{password}") }
    else # APIトークン認証
      { 'X-Cybozu-API-Token' => user }
    end
  end

  def parse_initial_args(args)
    case args.length
    when 0 then nil
    when 1
      password_or_options = args.first
      password_or_options.instance_of?(String) ? password_or_options : password_or_options.values_at(:password, :basic_user, :basic_password)
    when 2
      [args.first] + args.second.values_at(:basic_user, :basic_password)
    end
  end
end
