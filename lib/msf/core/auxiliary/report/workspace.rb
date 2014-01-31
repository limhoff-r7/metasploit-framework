module Msf::Auxiliary::Report::Workspace
  def inside_workspace_boundary?(ip)
    # allowed if database not connected
    allowed = true

    framework.db.with_connection do
      allowed = myworkspace.allow_actions_on?(ip)
    end

    allowed
  end

  # TODO fix this so that the method doesn't rely on side effects
  # for Spaghetti Monster's sake!
  def myworkspace
    @myworkspace = framework.db.with_connection {
      Mdm::Workspace.where(name: workspace_name).first
    }
  end
end