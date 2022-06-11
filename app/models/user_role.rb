# frozen_string_literal: true

# == Schema Information
#
# Table name: user_roles
#
#  id          :bigint(8)        not null, primary key
#  name        :string           default(""), not null
#  color       :string           default(""), not null
#  position    :integer          default(0), not null
#  permissions :bigint(8)        default(0), not null
#  highlighted :boolean          default(FALSE), not null
#  created_at  :datetime         not null
#  updated_at  :datetime         not null
#

class UserRole < ApplicationRecord
  FLAGS = {
    administrator: (1 << 0),
    view_devops: (1 << 1),
    view_audit_log: (1 << 2),
    view_dashboard: (1 << 3),
    manage_reports: (1 << 4),
    manage_federation: (1 << 5),
    manage_settings: (1 << 6),
    manage_blocks: (1 << 7),
    manage_taxonomies: (1 << 8),
    manage_appeals: (1 << 9),
    manage_users: (1 << 10),
    manage_invites: (1 << 11),
    manage_rules: (1 << 12),
    manage_announcements: (1 << 13),
    manage_custom_emojis: (1 << 14),
    manage_webhooks: (1 << 15),
    invite_users: (1 << 16),
    manage_roles: (1 << 17),
  }.freeze

  validates :name, presence: true, unless: :everyone?

  before_validation :set_position

  def self.everyone
    UserRole.find(-99)
  rescue ActiveRecord::RecordNotFound
    UserRole.create!(id: -99, permissions: FLAGS[:invite_users])
  end

  def everyone?
    id == -99
  end

  def permissions_as_hex
    '0x%016x' % permissions
  end

  def can?(*privileges)
    in_permissions?(:administrator) || privileges.any? { |privilege| in_permissions?(privilege) }
  end

  def overrides?(other_role)
    other_role.nil? || position > other_role.position
  end

  private

  def computed_permissions
    @computed_permissions ||= self.class.everyone.permissions | permissions
  end

  def in_permissions?(privilege)
    raise ArgumentError, "Unknown privilege: #{privilege}" unless FLAGS.key?(privilege)
    computed_permissions & FLAGS[privilege] == FLAGS[privilege]
  end

  def set_position
    self.position = -1 if everyone?
  end
end
