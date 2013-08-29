require 'spec_helper'

describe Metasploit::Framework::Memory do
	let(:environment) do
		described_class.environment
	end

  context 'environment' do
		subject do
			environment
		end

		it { should be_a ROM::Environment }

		it 'should call ROM::Environment#mapping' do
			ROM::Environment.any_instance.should_receive(:mapping).and_call_original

			environment
		end

		it 'should call seed' do
			Metasploit::Framework::Memory.should_receive(:seed).with(
					instance_of(ROM::Environment)
			)

			environment
		end

		context 'schema' do
			subject(:schema) do
				environment.schema
			end

			its([:architectures]) { should_not be_nil }
		end
	end

	context 'seed' do
		def seed(environment)
			described_class.seed(environment)
		end

		before(:each) do
			# clear the seeds seeded when the environment is created.
			ROM::Session.start(environment) do |session|
				session[:architectures].each do |architecture|
					# because ROM::Session queues changes until the next flush, it is safe
					# to delete inside an each as this delete does not affect that backing
					# array of Metasploit::Framework::Architectures.
					session[:architectures].delete(architecture)
				end

				session.flush
			end
		end

		it 'should add architecture seeds' do
			expect {
				seed(environment)
			}.to change(environment[:architectures], :count)
		end

		it 'should not add any new architectures if called repeatedly' do
			seed(environment)

			expect {
				seed(environment)
			}.to_not change(environment[:architectures], :count)
		end
	end
end
