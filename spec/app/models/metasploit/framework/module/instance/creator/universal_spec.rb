# -*- coding:binary -*-
require 'spec_helper'

#
# Core
#

# Temporary files
require 'tempfile'
# add mktmpdir to Dir
require 'tmpdir'

#
# Project
#

require 'msf/core'

describe Metasploit::Framework::Module::Instance::Creator::Universal do
  include_context 'Msf::Simple::Framework'

  let(:basename_prefix) do
    'rspec'
  end

  subject(:module_instance_creator) do
    framework.modules
  end

  context 'factories' do
    context 'metasploit_framework_module_instance_creator_universal' do
      include_context 'Msf::Simple::Framework'

      subject(:metasploit_framework_module_instance_creator_universal) do
        FactoryGirl.build(:metasploit_framework_module_instance_creator_universal)
      end

      # framework for Msf::Simple::Framework clean up
      let(:framework) do
        metasploit_framework_module_instance_creator_universal.framework
      end

      it { should be_valid }
    end
  end

  it_should_behave_like 'Metasploit::Framework::Module::Instance::Creator::Universal::Types'

  context '#create' do
    subject(:create) do
      module_instance_creator.create(full_name)
    end

    context 'with Mdm::Module::Class' do
      include_context 'database cleaner'
      include_context 'Metasploit::Framework::Spec::Constants cleaner'
      include_context 'metasploit_super_class_by_module_type'

      #
      # lets
      #

      let(:module_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: module_type
        )
      end

      let(:module_type) do
        Metasploit::Model::Module::Type::NON_PAYLOAD.sample
      end

      let(:full_name) do
        module_class.full_name
      end

      #
      # Callbacks
      #

      before(:each) do
        real_pathname = module_class.ancestors.first.real_pathname

        real_pathname.open('wb') do |f|
          f.puts "class Metasploit4 < #{metasploit_super_class}"
          f.puts "end"
        end
      end

      it 'uses Metasploit::Framework::Module::Cache#metasploit_class to get the metasploit_class' do
        expect(module_instance_creator.framework.cache).to receive(:metasploit_class).with(
                                                               an_instance_of(Mdm::Module::Class)
                                                           )

        create
      end

      it { should be_a Msf::Module }

      it 'is simplified' do
        expect(create).to be_a Msf::Simple::Framework::MODULE_SIMPLIFIER_BY_MODULE_TYPE[module_type]
      end

      context '#framework' do
        subject(:instance_framework) do
          create.framework
        end

        it 'is the Metasploit::Framework::Framework::Modules#framework' do
          expect(instance_framework).to eq(framework)
        end
      end
    end

    context 'without Mdm::Module::Class' do
      let(:full_name) do
        'non/existent/module/class'
      end

      it { should be_nil }
    end
  end
end
