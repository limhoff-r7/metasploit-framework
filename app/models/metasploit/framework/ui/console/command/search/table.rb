#
# Gems
#

require 'table_print'

class Metasploit::Framework::UI::Console::Command::Search::Table < Metasploit::Framework::UI::Console::Command::Base
  include Metasploit::Framework::UI::Console::Command::Child
  include Metasploit::Framework::UI::Console::Command::Search::Table::Columns
  include Metasploit::Framework::UI::Console::Command::Search::Table::TabCompletion
  include Metasploit::Framework::UI::Console::Command::Search::Table::ValidationErrors

  #
  # Attributes
  #

  # @!attribute [rw] formatted_operations
  #   Operations (<operator>:<value>) separated from parent options
  #
  #   @return [Array<String>]
  attr_writer :formatted_operations

  #
  # Validations
  #

  #
  # Method Validations
  #

  validate :visitor_valid

  #
  # Methods
  #

  def formatted_operations
    @formatted_operations ||= []
  end

  def query
    @query ||= Metasploit::Model::Search::Query.new(
        formatted_operations: formatted_operations,
        klass: Mdm::Module::Instance
    )
  end

  def visitor
    @visitor ||= MetasploitDataModels::Search::Visitor::Relation.new(query: query)
  end

  protected

  def run_with_valid
    TablePrint::Config.max_width = width

    printer = TablePrint::Printer.new(
        visitor.visit,
        column_name_set.to_a
    )

    print_line printer.table_print
  end

  private

  def visitor_valid
    unless visitor.valid?
      errors.add(:visitor, :invalid)
    end
  end
end