require 'pathname'
require 'rubygems'
require 'bundler/setup'
Bundler.require(:default)

require 'minitest/autorun'
require 'byebug'

module Minitest
  module Declarative
    def test(name, &block)
      test_name = "test_#{name.gsub(/\s+/, '_')}".to_sym
      defined = method_defined? test_name
      raise "#{test_name} is already defined in #{self}" if defined
      if block_given?
        define_method(test_name, &block)
      else
        define_method(test_name) do
          flunk "No implementation provided for #{name}"
        end
      end
    end
  end
end

Minitest::Test.extend Minitest::Declarative

class TestRequest
  attr_reader :path, :query_string, :content_type, :method
  
  def initialize(path, query_string: nil, content_type: nil, method: :get)
    @path, @query_string, @content_type, @method = path, query_string, content_type, method
  end
  
  %i[get post patch delete].each do |http_method|
    define_method("#{http_method}?") { method == http_method }
  end
end
