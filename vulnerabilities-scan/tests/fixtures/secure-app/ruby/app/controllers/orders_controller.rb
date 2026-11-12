# Secure look-alike of the Rails controller.
require "bcrypt"
require "json"

class OrdersController < ApplicationController
  # Authentication and authorization run before every action.
  before_action :authenticate

  def index
    # Bound parameter, not interpolation.
    @orders = Order.where("name = ?", params[:term])
  end

  def report
    # Argument vector, no shell interpolation.
    system("tar", "-czf", "/tmp/report.tar", params[:name])
    render plain: "ok"
  end

  def download
    # Basename only, joined under the data root.
    name = File.basename(params[:file])
    send_data File.read(File.join("/srv/data", name))
  end

  def restore
    # Structured JSON, not Marshal.
    @state = JSON.parse(params[:state])
  end

  def import_yaml
    # Safe YAML loading.
    @config = YAML.safe_load(params[:config])
  end

  def digest
    # Adaptive hash.
    BCrypt::Password.create(params[:password])
  end

  def promote
    # The role comes from the caller's stored record, never the request.
    raise Forbidden unless current_user.admin?
    render json: { role: current_user.role }
  end

  def show
    # Escaped output, not html_safe.
    render html: ERB::Util.html_escape(params[:note])
  end
end
