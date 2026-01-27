require 'pathname'
require 'stringio'
require 'rack/attack'
require_relative 'shield/version'
require_relative 'shield/responder'
require_relative 'shield/request_ext'

module Rack
  module Shield
    DEFAULT_PATHS = [
      '/actuator/gateway/routes',
      '/actuator/health',
      '/admin/uploadify/',
      '/adminer',
      'alfacgiapi',
      'ALFA_DATA',
      '/api/v2/cmdb/system',
      '/api/v2/static/not.found',
      '/appsuite/signin',
      '/aspera/faspex',
      '/aspnet-ajax/',
      '/.astro/',
      '/axis2/axis2-admin',
      '/bakula-web',
      '/boaform/',
      '/browsedisk',
      'cgialfa',
      'cgi-bin',
      'com.vmware.vsan.client.services',
      '/Config/SaveUploadedHotspotLogoFile',
      '/+CSCOT+/',
      'deployment-config.json',
      '/(download)/',
      '/downloadMainLog',
      '/drupal.js',
      '/env.d.ts',
      'etc/passwd',
      '/faspex/',
      'ftpsync.settings',
      '/groovyconsole',
      '/HNAP1',
      '/geoserver/web',
      '/_ignition/',
      '/includes/',
      '/io.ox/',
      '/ipython/',
      '/jenkins/',
      '/jmx-console',
      '/joomla/',
      '/js/varien/',
      '/mage/',
      '/magento/',
      '/magento_version',
      '/mambo/',
      '/meta-data/identity-credentials/',
      '/mifs/',
      '/mPlayer',
      '/nacos/',
      '/nginx.conf',
      '/nice%20ports',
      '/nmaplowercheck',
      '/OASREST/',
      '/officescan/',
      '/owa/auth/',
      '/ox6/',
      '/php/',
      '.php/',
      '/phpinfo',
      'phpmyadmin',
      '/phpunit/',
      '/pma/',
      '/Portal0000.htm',
      '/Portal.mwsl',
      '/_profiler/latest',
      'RELEASE_NOTES.txt',
      '/RELEASE_NOTES.txt',
      '/remote/logincheck',
      '/rest/applinks/',
      '/runtime~main.js',
      '/SaveUploadedHotspotLogoFile',
      '/SDK/webLanguage',
      '/seeyon/htmlofficeservlet',
      '/servlet/',
      '/SiteLoader',
      '/snort/',
      '/solr/admin/',
      'sqlbuddy',
      '/.ssh/',
      '/stalker_portal/',
      '/telescope/requests',
      '/teorema505',
      '/tkset/',
      '/UploadServlet',
      '/@vite/',
      '/varien/js.js',
      '/VisionHubWebApi/',
      '/WEB-INF/',
      '/WEB-INF/',
      '/_wpeprivate/',
      '/ws_utc/',
      /\/wp-(includes|content|admin|json|config)/,
      /\.(php\d?|cgi|asp|aspx|env|shtml|log|(my)?sql(\.tar)?(\.t?(gz|zip))?|cfm|cmd|py|lasso|e?rb|pl|jsp|do|action|sh|dll|lsp|ehp)\z/i,
      /\A\/"/,
      /\/\.(hg|git|svn|bzr|htaccess|ftpconfig|vscode|remote-sync|aws|env|DS_Store)/,
      /(my)?sql-backup/,
      /\/old\/?\z/,
      /\A\/old-wp/,
      /\A\/(wordpress|wp)(\/|\z)/,
      /Open-Xchange/i]

    DEFAULT_QUERIES = [
      /SELECT.+FROM.+/i,
      /SELECT.+COUNT/i,
      /SELECT.+UNION/i,
      /UNION.+SELECT/i,
      /INFORMATION_SCHEMA/i,
      /phpcredits/,
      '--%20',
      '-- ',
      '%2Fscript%3E',
      '<script>', '</script>',
      '<php>', '</php>',
      'XDEBUG_SESSION_START',
      'phpstorm',
      '<php>',
      'onload=confirm',
      'HelloThinkCMF',
      'XDEBUG_SESSION_START'
    ]

    DEFAULT_BODIES = [
      'OKMLlKlV',
      'DBMS_PIPE.RECEIVE_MESSAGE',
      'encodeURIComponent(',
      '.execSync(',
      /eth_getWork/,
      'mainModule.require',
      'node:child_process',
      'Object.assign(',
      /SELECT.+FROM.+/i,
      /SELECT.+COUNT/i,
      /SELECT.+UNION/i,
      /UNION.+SELECT/i,
      /INFORMATION_SCHEMA/i,
      /WAITFOR DELAY/i,
      /FROM PG_SLEEP/i,
      'String.fromCharCode',
      '/tmp/xd.sh',
      '.toString()',
      '/xmrig',
      /CHR\(\d+\)/i,
      /UNION.+SELECT/i
    ]

    DEFAULT_CHECKS = [
    ]

    class << self

      attr_accessor :paths, :queries, :bodies, :checks, :responder
  
      def evil?(req)
        evil_paths?(req) || evil_queries?(req) || evil_checks?(req) || evil_bodies?(req)
      end
      
      def template
        Pathname.new(__FILE__).dirname.join('..', '..', '..', 'templates', 'shield.html')
      end
  
      private
  
      def match?(obj, matcher)
        case matcher
        when String then obj.include?(matcher)
        when Regexp then obj.match?(matcher)
        when Proc   then matcher.call(obj)
        end
      end
      
      def evil_paths?(req)
        req.path && paths.any? { |matcher| match?(req.path, matcher) }
      end
      
      def evil_queries?(req)
        req.query_string && queries.any? { |matcher| match?(req.query_string, matcher) }
      end
      
      def evil_checks?(req)
        checks.any? { |matcher| match?(req, matcher) }
      end
      
      def evil_bodies?(req)
        return false unless req.post? || req.put? || req.patch?
        return false unless body = req.raw_post_data
        return false if body.empty?
        bodies.any? { |matcher| match?(body, matcher) }
      end
    end

    self.paths     = DEFAULT_PATHS.dup
    self.queries   = DEFAULT_QUERIES.dup
    self.bodies    = DEFAULT_BODIES.dup
    self.checks    = DEFAULT_CHECKS.dup
    self.responder = Responder

  end
end
