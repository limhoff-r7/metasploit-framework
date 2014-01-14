class Metasploit::Framework::Attempt::Vuln::Creation < Metasploit::Framework::Attempt::Creation::Single
  def self.attempt_type
    :vuln
  end
end