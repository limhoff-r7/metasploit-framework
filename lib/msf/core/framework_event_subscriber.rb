class Msf::FrameworkEventSubscriber
  include Framework::Offspring

  def initialize(framework)
    self.framework = framework
  end

  def report_event(data)
    framework.db.report_event(data)
  end

  include Msf::GeneralEventSubscriber

  #
  # Generic handler for module events
  #
  def module_event(name, instance, opts={})
    framework.db.with_connection {
      event = {
          :workspace => instance.workspace_record,
          :name      => name,
          :username  => instance.owner,
          :info => {
              :module_name => instance.full_name,
              :module_uuid => instance.uuid
          }.merge(opts)
      }

      report_event(event)
    }
  end

  ##
  # :category: ::Msf::GeneralEventSubscriber implementors
  def on_module_run(instance)
    opts = { :datastore => instance.data_store.to_h }
    module_event('module_run', instance, opts)
  end

  ##
  # :category: ::Msf::GeneralEventSubscriber implementors
  def on_module_complete(instance)
    module_event('module_complete', instance)
  end

  ##
  # :category: ::Msf::GeneralEventSubscriber implementors
  def on_module_error(instance, exception=nil)
    module_event('module_error', instance, :exception => exception.to_s)
  end

  include ::Msf::UiEventSubscriber
  ##
  # :category: ::Msf::UiEventSubscriber implementors
  def on_ui_command(command)
    report_event(:name => "ui_command", :info => {:command => command})
  end

  ##
  # :category: ::Msf::UiEventSubscriber implementors
  def on_ui_stop()
    report_event(:name => "ui_stop")
  end

  ##
  # :category: ::Msf::UiEventSubscriber implementors
  def on_ui_start(rev)
    #
    # The database is not active at startup time unless msfconsole was
    # started with a database.yml, so this event won't always be saved to
    # the db.  Not great, but best we can do.
    #
    info = { :revision => rev }
    report_event(:name => "ui_start", :info => info)
  end

  require 'msf/core/session'

  include ::Msf::SessionEvent

  #
  # Generic handler for session events
  #
  def session_event(name, session, opts={})
    address = session.session_host

    if not (address and address.length > 0)
      elog("Session with no session_host/target_host/tunnel_peer")
      dlog("#{session.inspect}", LEV_3)
      return
    end

    framework.db.with_connection do
      ws = framework.db.find_workspace(session.workspace)
      event = {
          :workspace => ws,
          :username  => session.username,
          :name => name,
          :host => address,
          :info => {
              :session_id   => session.sid,
              :session_info => session.info,
              :session_uuid => session.uuid,
              :session_type => session.type,
              :username     => session.username,
              :target_host  => address,
              :via_exploit  => session.via_exploit,
              :via_payload  => session.via_payload,
              :tunnel_peer  => session.tunnel_peer,
              :exploit_uuid => session.exploit_uuid
          }.merge(opts)
      }
      report_event(event)
    end
  end


  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_open(session)
    opts = { :datastore => session.exploit_data_store.to_h, :critical => true }
    session_event('session_open', session, opts)
    framework.db.open_session(session)
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_upload(session, lpath, rpath)
    session_event('session_upload', session, :local_path => lpath, :remote_path => rpath)
    framework.db.report_session_event({
                                          :etype => 'upload',
                                          :session => session,
                                          :local_path => lpath,
                                          :remote_path => rpath
                                      })
  end
  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_download(session, rpath, lpath)
    session_event('session_download', session, :local_path => lpath, :remote_path => rpath)
    framework.db.report_session_event({
                                          :etype => 'download',
                                          :session => session,
                                          :local_path => lpath,
                                          :remote_path => rpath
                                      })
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_close(session, reason='')
    session_event('session_close', session)
    if session.db_record
      # Don't bother saving here, the session's cleanup method will take
      # care of that later.
      session.db_record.close_reason = reason
      session.db_record.closed_at = Time.now.utc
    end
  end

  #def on_session_interact(session)
  #	$stdout.puts('session_interact', session.inspect)
  #end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_command(session, command)
    session_event('session_command', session, :command => command)
    framework.db.report_session_event({
                                          :etype => 'command',
                                          :session => session,
                                          :command => command
                                      })
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_output(session, output)
    # Break up the output into chunks that will fit into the database.
    buff = output.dup
    chunks = []
    if buff.length > 1024
      while buff.length > 0
        chunks << buff.slice!(0,1024)
      end
    else
      chunks << buff
    end
    chunks.each { |chunk|
      session_event('session_output', session, :output => chunk)
      framework.db.report_session_event({
                                            :etype => 'output',
                                            :session => session,
                                            :output => chunk
                                        })
    }
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_route(session, route)
    framework.db.report_session_route(session, route)
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_route_remove(session, route)
    framework.db.report_session_route_remove(session, route)
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_script_run(session, script)
    framework.db.report_session_event({
                                          :etype => 'script_run',
                                          :session => session,
                                          :local_path => script
                                      })
  end

  def on_session_module_run(session, mod)
    framework.db.report_session_event(
        etype: 'module_run',
        local_path: mod.full_name,
        session: session
    )
  end
end
