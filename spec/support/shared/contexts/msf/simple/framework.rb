# -*- coding:binary -*-
require 'msf/base/simple/framework'
require 'metasploit/framework'

shared_context 'Msf::Simple::Framework' do
  include_context 'Metasploit::Framework::Thread::Manager cleaner' do
    let(:thread_manager) do
      # don't create thread manager if example didn't create it
      framework.instance_variable_get :@threads
    end
  end

	let(:framework) do
    FactoryGirl.create(:msf_simple_framework)
	end
end
