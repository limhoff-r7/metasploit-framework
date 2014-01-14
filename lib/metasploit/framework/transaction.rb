module Metasploit::Framework::Transaction
  def transaction(&block)
    ActiveRecord::Base.connection_pool.with_connection do
      # transaction so that bulk removes and adds are performed together
      ActiveRecord::Base.transaction do
        block.call
      end
    end
  end
end