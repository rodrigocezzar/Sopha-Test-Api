# frozen_string_literal: true

module Api
  module V1
    class UsersController < ApplicationController
      before_action :authorized, except: [:create]
      # before_action :set_user, only: %i[show update destroy]

      def index
        @users = User.page(params[:page]).per(5)
      end

      def show
        @user = User.where(id: params[:id]).page(params[:page]).per(5)
      end

      def create
        @user = User.new(user_params)

        if User::CreateService.new(@user).call
          render json: { message: 'Usuário Criado com Sucesso' }, status: :created
        else
          render json: { errors: @user.errors }, status: :unprocessable_entity
        end
      end

      def update
        @user = User.find_by(id: params[:id])

        return render json: { errors: 'Usuário inexistente' }, status: :not_found if @user.nil?

        @service = User::UpdateService.new(@user, user_params)

        if @service.call
          render json: { message: 'Usuário Atualizado' }, status: :ok
        else
          render json: { errors: @service.errors }, status: :unprocessable_entity
        end
      end

      def destroy
        @user = User.find_by(id: params[:id])

        return render json: { errors: 'Usuário inexistente' }, status: :not_found if @user.nil?

        render json: { message: '' }, status: :no_content if @user.destroy
      end

      private

      def paginatable_model
        User
      end

      def set_user
        @user = User.find(params[:id])
      end

      def user_params
        params.permit(:name, :email, :password)
      end
    end
  end
end
