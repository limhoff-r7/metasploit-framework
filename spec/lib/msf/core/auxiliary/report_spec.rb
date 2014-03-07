require 'spec_helper'

describe Msf::Auxiliary::Report do
  include_context 'database cleaner'
  include_context 'Msf::Simple::Framework'

  subject(:auxiliary_instance) do
    auxiliary_class.new(framework: framework)
  end

  let(:auxiliary_class) do
    described_class = self.described_class

    Class.new(Msf::Auxiliary) do
      include described_class
    end
  end

  it_should_behave_like 'Msf::Auxiliary::Report'
end