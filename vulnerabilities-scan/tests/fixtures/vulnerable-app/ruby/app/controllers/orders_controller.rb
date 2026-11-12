# Intentionally vulnerable Rails controller for the fixture.
require "digest"
require "yaml"

class OrdersController < ApplicationController
  # missing-authorization: the authorization filter is turned off
  skip_before_action :authenticate

  def index
    # rb-sql-concat: ActiveRecord query built by interpolation
    @orders = Order.where("name = '#{params[:term]}'")
  end

  def report
    # cmd-ruby: shell execution with interpolation
    system("tar -czf /tmp/report.tar #{params[:name]}")
    render plain: "ok"
  end

  def download
    # path-traversal: request data used to build the path
    send_data File.read("/srv/data/#{params[:file]}")
  end

  def restore
    # unsafe-deserialization: Marshal on untrusted input
    @state = Marshal.load(params[:state])
  end

  def import_yaml
    # unsafe-deserialization: YAML.load without safe_load
    @config = YAML.load(params[:config])
  end

  def digest
    # weak-password-hashing: fast digest for a password
    Digest::MD5.hexdigest(params[:password])
  end

  def promote
    # missing-authorization / business-logic: role and price from the client
    role = params[:role]
    price = params[:price]
    render json: { role: role, price: price }
  end

  def show
    # xss-reflected: markup marked html_safe
    render html: params[:note].html_safe
  end
end
