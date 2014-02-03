module Msf::EvasiveTCP
  attr_accessor :_send_size, :_send_delay, :evasive

  def denagle
    begin
      setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    rescue ::Exception
    end
  end

  def write(buf, opts={})

    return super(buf, opts) if not @evasive

    ret = 0
    idx = 0
    len = @_send_size || buf.length

    while(idx < buf.length)

      if(@_send_delay and idx > 0)
        ::IO.select(nil, nil, nil, @_send_delay)
      end

      pkt = buf[idx, len]

      res = super(pkt, opts)
      flush()

      idx += len
      ret += res if res
    end
    ret
  end
end
