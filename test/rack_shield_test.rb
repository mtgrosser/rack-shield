require_relative 'test_helper'

class RackShieldTest < Minitest::Test
  test 'Version' do
    refute_nil Rack::Shield::VERSION
  end

  test 'Wordpress is blocked' do
    assert_blocked '/wp-admin'
  end
  
  test 'Illegal file extensions are blocked' do
    ['/foo/bar.cgi',
      '/foobar.mysql.tar',
      '/foo.sql',
      '/foo.mysql',
      '/../../etc/passwd',
      '/phpmyadmin',
      '/foo.mysql.zip',
      '/foo.sql.zip'
    ].each { |path| assert_blocked path }
  end

  test 'Wordpress is blocked with and without trailing slash' do
    assert_blocked '/wordpress'
    assert_blocked '/wp'
    assert_blocked '/wordpress/'
    assert_blocked '/wp/'
  end
  
  test 'Repositories are blocked' do
    assert_blocked '/foobar/.git'
    assert_blocked '/.hg/hgrc'
    assert_blocked '/foo/.svn/format'
  end
  
  test 'ZIP files are not blocked' do
    assert_not_blocked '/foo.bar.zip'
  end
  
  test 'SQL injection is blocked' do
    assert_blocked '/posts/new', query_string: 'author_id=95%27%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL--%20HDgn'
  end
  
  test 'Path starting with quote is blocked' do
    assert_blocked '/"foobar.html'
  end
  
  test 'HEAD returns empty body' do
    status, _, body = Rack::Shield::Responder.new(TestRequest.new('/site.html', method: :head)).render
    assert_equal 403, status
    assert_empty body
  end

  test 'Custom proc matchers' do
    checks = Rack::Shield.checks.dup
    begin
      Rack::Shield.checks << ->(req) { req.post? && req.content_type && req.content_type.include?('FOOBARFOO') }
      assert_blocked '/posts/create', content_type: 'multipart/form-data; boundary=------------------------FOOBARFOO', method: :post
    ensure
      Rack::Shield.checks.replace checks
    end
  end
  
  test 'Custom POST body checks' do
    checks = Rack::Shield.checks.dup
    begin
      Rack::Shield.checks << lambda do |req|
        req.post? && req.content_type && req.content_type.include?('application/json') && req.raw_post_data && req.raw_post_data.start_with?('foo=true')
      end
      assert_blocked '/signup', content_type: 'application/json;', method: :post, body: 'foo=true'
      assert_not_blocked '/signup', content_type: 'application/json;', method: :post, body: '{"foo":true}'
    ensure
      Rack::Shield.checks.replace checks
    end
  end
  
  test 'Body checks' do
    bodies = Rack::Shield.bodies.dup
    begin
      Rack::Shield.bodies << /INFORMATION_SCHEMA/i
      assert_blocked '/signup', content_type: 'application/json', method: :put, body: 'SELECT * FROM INFORMATION_SCHEMA'
    ensure
      Rack::Shield.bodies.replace bodies
    end
  end

  test 'Custom checks' do
    begin
      checks = Rack::Shield.checks.dup
      Rack::Shield.checks << lambda { |req| req.content_type.include?('foop') }
      assert_blocked '/', content_type: 'application/foop'
    ensure
      Rack::Shield.checks.replace checks
    end
  end
  
  private
  
  def assert_blocked(path, **opts)
    message = "Expected #{path.inspect} "
    message << "with query #{opts[:query_string].inspect} " if opts[:query_string]
    message << "and method #{opts[:method].to_s.upcase} " if opts[:method]
    message << "to be blocked, but wasn't"
    assert Rack::Shield.evil?(TestRequest.new(path, **opts)), message
  end
  
  def assert_not_blocked(path, **opts)
    message = "Expected #{path.inspect} "
    message << "with query #{opts[:query_string].inspect} " if opts[:query_string]
    message << "and method #{opts[:method].to_s.upcase} " if opts[:method]
    message << "not to be blocked, but was"
    assert !Rack::Shield.evil?(TestRequest.new(path, **opts)), message
  end
end
