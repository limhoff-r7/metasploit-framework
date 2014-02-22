# Handle common code for finding the database.yml, picking the environment and handling errors when calling
# {Msf::DBManager#connect}.
class Metasploit::Framework::DatabaseConnection < Metasploit::Model::Base
  include ActiveModel::Validations::Callbacks

  #
  # Attributes
  #

  # @!attribute [rw] database_yaml_pathname
  #   @return [Pathname] `Pathname` to `database.yml`
  attr_writer :database_yaml_pathname

  # @!attribute [rw] db_manager
  #   Database manager to initiate connection.
  #
  #   @return [Msf::DBManager]
  attr_accessor :db_manager

  # @!attribute [rw] environment
  #   The environment whose {#configuration} to load from {#configuration_by_environment}.
  #
  #   @return [String]

  #
  #
  # Validations
  #
  #

  #
  # Method Validations
  #

  validate :database_yaml_pathname_exists
  validate :database_yaml_pathname_readable
  validate :db_manager_valid

  #
  # Attribute Validations
  #

  validates :configuration,
            presence: true
  validates :connected?,
            inclusion: {
                in: [true]
            }
  validates :db_manager,
            presence: true

  #
  # Methods
  #

  def configuration
    configuration_by_environment[environment]
  end

  def configuration_by_environment
    begin
      erb_content = database_yaml_pathname.read
    rescue Errno::EACCES, Errno::ENOENT
      {}
    else
      erb = ERB.new(erb_content)
      yaml_content = erb.result
      YAML::load(yaml_content)
    end
  end

  # Whether the {#db_manager} is connected. Attempts to connect to the databse
  #
  # @return [void]
  def connected?
    if db_manager
      if db_manager.valid? && configuration.present?
        db_manager.connect(configuration)
      else
        db_manager.connected?
      end
    else
      false
    end
  end

  # Defaults to `ENV['MSF_DATABASE_CONFIG']` first and fails back to `config/database.yml`.
  #
  # @return [Pathname] `Pathname` to `database.yml`
  def database_yaml_pathname
    unless @database_yaml_pathname
      database_yaml_path = ENV['MSF_DATABASE_CONFIG']
      database_yaml_path ||= File.join(Msf::Config.get_config_root, 'database.yml')
      @database_yaml_pathname = Pathname.new(database_yaml_path)
    end

    @database_yaml_pathname
  end

  # Defaults to {Metasploit::Framework.env}.
  #
  # @return [ActiveSupport::StringInquirer]
  def environment
    @environment ||= Metasploit::Framework.env
  end

  # Set the environment to use to look up the database connection options.
  #
  # @return [ActiveSupport::StringInquirer]
  def environment=(environment)
    if environment
      @environment = ActiveSupport::StringInquirer.new(environment)
    else
      @environment = environment
    end
  end

  private

  # Validates that {#database_yaml_pathname} exists.
  #
  # @return [void]
  def database_yaml_pathname_exists
    unless database_yaml_pathname.exist?
      errors.add(:database_yaml_pathname, :non_existent)
    end
  end

  # Validates that {#database_yaml_pathname} is readable.
  #
  # @return [void]
  def database_yaml_pathname_readable
    unless database_yaml_pathname.readable?
      errors.add(:database_yaml_pathname, :unreadable)
    end
  end

  # Validates {#db_manager} after {#connect}.
  #
  # @return [void]
  def db_manager_valid
    unless !db_manager || db_manager.valid?
      errors.add(:db_manager, :invalid)
    end
  end
end