# frozen_string_literal: true

class CreateUsers < ActiveRecord::Migration[5.1]
  def change
    create_table :users do |t|
      t.string :name
      t.string :email, unique: true, index: true
      t.string :password_digest

      t.timestamps
    end
  end
end
