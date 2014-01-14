class Msf::RouteArray < Array
  def initialize(sess)
    self.session = sess
    super()
  end

  def <<(val)
    session.framework.events.on_session_route(session, val)
    super
  end

  def delete(val)
    session.framework.events.on_session_route_remove(session, val)
    super
  end

  attr_accessor :session
end