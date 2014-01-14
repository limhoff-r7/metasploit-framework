module Msf::DBManager::Workspace
  def workspace=(workspace)
    if workspace
      @workspace_name = workspace.name
    else
      @workspace_name = nil
    end
  end

  def workspace(options={})
    options.assert_valid_keys(:name)

    find_workspace(options[:name] || @workspace_name)
  end

  attr_accessor :workspace_name

  def default_workspace
    with_connection {
      ::Mdm::Workspace.default
    }
  end

  def find_workspace(name)
    with_connection {
      ::Mdm::Workspace.find_by_name(name)
    }
  end

  #
  # Creates a new workspace in the database
  #
  def add_workspace(name)
    with_connection {
      ::Mdm::Workspace.find_or_create_by_name(name)
    }
  end

  def workspaces
    with_connection {
      ::Mdm::Workspace.find(:all)
    }
  end
end