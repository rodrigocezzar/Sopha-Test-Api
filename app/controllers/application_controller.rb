# frozen_string_literal: true

class ApplicationController < ActionController::API
  before_action :authorized

  def encode_token(payload)
    JsonWebToken.jwt_encode(payload)
  end

  def auth_header
    request.headers['Authorization']
  end

  def decoded_token
    return unless auth_header

    token = auth_header.split(' ')[1]
    begin
      JsonWebToken.jwt_decode(token)
    rescue CustomError::InvalidToken
      nil
    end
  end

  def current_user
    return unless decoded_token

    user_id = decoded_token.is_a?(Array) ? decoded_token[0]['user_id'] : decoded_token['user_id']
    @user = User.find_by(id: user_id)
  end

  def logged_in?
    !!current_user
  end

  def authorized
    return if logged_in?

    render json: { aviso: 'É necessário efetuar o login antes de utilizar esse endpointttll' },
           status: :unauthorized
  end
end
