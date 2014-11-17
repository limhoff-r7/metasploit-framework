module Msf::Ui::Console::CommandDispatcher::Db::Workspace
  def cmd_workspace(*args)
    return unless active?
    ::ActiveRecord::Base.connection_pool.with_connection {
      while (arg = args.shift)
        case arg
        when '-h', '--help'
          cmd_workspace_help
          return
        when '-a', '--add'
          adding = true
        when '-d', '--del'
          deleting = true
        when '-r', '--rename'
          renaming = true
        else
          names ||= []
          names << arg
        end
      end

      if adding and names
        # Add workspaces
        workspace = nil
        names.each do |name|
          workspace = framework.db.add_workspace(name)
          print_status("Added workspace: #{workspace.name}")
        end
        framework.db.workspace = workspace
      elsif deleting and names
        switched = false
        # Delete workspaces
        names.each do |name|
          workspace = framework.db.find_workspace(name)
          if workspace.nil?
            print_error("Workspace not found: #{name}")
          elsif workspace.default?
            workspace.destroy
            workspace = framework.db.add_workspace(name)
            print_status("Deleted and recreated the default workspace")
          else
            # switch to the default workspace if we're about to delete the current one
            if framework.db.workspace.name == workspace.name
              framework.db.workspace = framework.db.default_workspace
              switched = true
            end
            # now destroy the named workspace
            workspace.destroy
            print_status("Deleted workspace: #{name}")
          end
        end
        print_status("Switched workspace: #{framework.db.workspace.name}") if switched
      elsif renaming
        if names.length != 2
          print_error("Wrong number of arguments to rename")
          return
        end
        old, new = names

        workspace = framework.db.find_workspace(old)

        old_is_active = (framework.db.workspace == workspace)
        recreate_default = workspace.default?

        if workspace.nil?
          print_error("Workspace not found: #{name}")
          return
        end

        if framework.db.find_workspace(new)
          print_error("Workspace exists: #{new}")
          return
        end

        workspace.name = new
        workspace.save!

        # Recreate the default workspace to avoid errors
        if recreate_default
          framework.db.add_workspace(old)
          print_status("Recreated default workspace after rename")
        end

        # Switch to new workspace if old name was active
        if old_is_active
          framework.db.workspace = workspace
          print_status("Switched workspace: #{framework.db.workspace.name}")
        end
      elsif names
        name = names.last
        # Switch workspace
        workspace = framework.db.find_workspace(name)
        if workspace
          framework.db.workspace = workspace
          print_status("Workspace: #{workspace.name}")
        else
          print_error("Workspace not found: #{name}")
          return
        end
      else
        # List workspaces
        framework.db.workspaces.each do |s|
          pad = (s.name == framework.db.workspace.name) ? "* " : "  "
          print_line("#{pad}#{s.name}")
        end
      end
    }
  end

  def cmd_workspace_help
    print_line "Usage:"
    print_line "    workspace                  List workspaces"
    print_line "    workspace [name]           Switch workspace"
    print_line "    workspace -a [name] ...    Add workspace(s)"
    print_line "    workspace -d [name] ...    Delete workspace(s)"
    print_line "    workspace -r <old> <new>   Rename workspace"
    print_line "    workspace -h               Show this help information"
    print_line
  end

  def cmd_workspace_tabs(str, words)
    return [] unless active?
    framework.db.workspaces.map { |s| s.name } if (words & ['-a', '--add']).empty?
  end
end
