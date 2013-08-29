#
# Standard Library
#
require 'securerandom'

#
# Gems
#
require 'rom'
require 'rom/support/axiom/adapter/memory'

#
# Project
#

require 'metasploit/framework'

module Metasploit
	module Framework
		module Memory
			BITS_PER_BYTE = 8
			RANDOM_ID_BYTES = 16
			RANDOM_ID_BITS = RANDOM_ID_BYTES * BITS_PER_BYTE
			RANDOM_ID_N = 2 ** RANDOM_ID_BITS

			#
			# Methods
			#

			# An environment for in-memory models.
			#
			# @return [ROM::Environment] environment with schema and mapping already
			#   declared
			def self.environment
				environment = ROM::Environment.setup(
						memory: 'memory://metasploit-framework'
				)

				environment.schema do
					base_relation :architectures do
						repository :memory

						attribute :id, Integer
						attribute :abbreviation, String
						attribute :bits, Integer
						attribute :endianness, String
						attribute :family, String
						attribute :summary, String

						key :id
					end
				end

				environment.mapping do
					architectures do
						map :id,
								:abbreviation,
								:bits,
								:endianness,
								:family,
								:summary

						model Metasploit::Framework::Architecture
					end
				end

				seed(environment)

				environment
			end


			# Generates a random ID with the same number of bits as
			# `SecureRandom.uuid`
			#
			# @return [Integer]
			# @see SecureRandom.random_number
			def self.random_id
				SecureRandom.random_number(RANDOM_ID_N)
			end

			def self.seed(environment)
				ROM::Session.start(environment) do |session|
					Metasploit::Model::Architecture::SEED_ATTRIBUTES.each do |attributes|
						relation = session[:architectures].restrict(attributes)

						if relation.count == 0
							seed = Metasploit::Framework::Architecture.new(attributes)
							seed.id = random_id

							unless seed.valid?
								raise Metasploit::Framework::ModelInvalid.new(seed)
							end

							# XXX not sure why I need to manually call track since the
							# rom-rb.org shows me just using save.
							session[:architectures].track(seed)
							session[:architectures].save(seed)
						end
					end

					session.flush
				end
			end
		end
	end
end
