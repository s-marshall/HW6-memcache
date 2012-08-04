require 'sinatra'
require 'haml'
require 'data_mapper'
require 'dm-postgres-adapter'
require 'pg'
require 'thin'
require './secure'
require 'dalli'

enable :sessions
use Rack::CommonLogger
enable :logging

DataMapper::setup(:default, ENV['DATABASE_URL'] || 'postgres://localhost/password.db')

class Password
  include DataMapper::Resource

  property :id, Serial
  property :username, String
  property :password, Text
end

DataMapper::setup(:default, ENV['DATABASE_URL'] || 'postgres://localhost/blogdb')
class Post
  include DataMapper::Resource

  property :id, Serial
  property :subject, String
  property :content, Text
  property :created, DateTime, :default => Time.now
  property :permalink, String

  before :valid?, :set_permalink

  private
    def set_permalink
      self.permalink = id
    end
end

DataMapper.finalize
Password.auto_upgrade!
Post.auto_upgrade!

class NewestPost
  attr_accessor :subject, :content

  def initialize
    @subject = ''
    @content = ''
  end
end

$CACHE = Dalli::Client.new('localhost:11211')

def current_time
  return Time.now.sec + 60 * Time.now.min
end

$start_time = current_time
$post_start_time = $start_time

def get_listing(key)
  string = $CACHE.get(key)
  listing = nil
  if string != nil
    listing = Marshal.load(string)
  end
  return listing
end

def cache(key, listing)
  string = Marshal.dump(listing)
  $CACHE.set(key, string)
end

def get_top_ten_blogs(update = false)
  key = 'top'
  blog_listing = get_listing(key)

  if (blog_listing == nil) || update
    logger.info 'DB Query'
    $start_time = current_time
    blog_listing = Post.all(:order => :created.desc, :limit => 10)
    cache(key, blog_listing)
  end
  return blog_listing
end

def get_perma_post(k)
  key = k.to_s
  post_listing = get_listing(key)

  if (post_listing == nil)
    logger.info 'permalink DB Query'
    $post_start_time = current_time
    post_listing = Post.first(:id => k)
    cache(key, post_listing)
  end
  return post_listing
end

def render_blogs(subject = '', content = '', error = '')
  @age = current_time - $start_time
  blog_listing = get_top_ten_blogs
  haml :blogs, :locals => {:subject => subject, :content => content, :error => error, :blog_listing => blog_listing}
end

def render_post(id)
  @age = current_time - $post_start_time
  perma_post = get_perma_post(id.to_s)
  haml :post, :locals => {:subject => perma_post.subject, :content => perma_post.content}
end

def validate_username(username)
  username =~ /^[a-zA-Z0-9_-]{3,20}$/
end

def validate_password(password)
  password =~ /^.{3,20}$/
end

def validate_email(email)
  email =~ /^[\S]+@[\S]+\.[\S]+$/
end

def write_form(username_error='', password_error='', verify_error='', email_error='')
  @invalid_username = username_error
  @invalid_password = password_error
  @invalid_verify = verify_error
  @invalid_email = email_error

  haml :signup, :locals =>
    {	:username => params[:username],
     	:password => params[:password],
    	:verify => params[:verify],
    	:email => params[:email]
    }
end

def name_in_database?(name)
  entries = Password.all
  entries.each do |e|
    return true if e.username == make_secure_value(name)
  end
  return nil
end

def name_and_password_in_database?(name, password)
  secure_name = make_secure_value(name)
  pw = Password.all(:username => secure_name)
  if pw[0]
    pw[0].password =~ /^([^,]*),(.*)/
    if (get_value_from_hash(pw[0].username) == name) && check_for_validity(name, password, pw[0].password)
      return true
    end
  else
    return nil
  end
end

newest_post = NewestPost.new

get '/signup' do
  haml :signup
end

post '/signup' do
  @valid_input = true
  session[:valid_password] = false

  if validate_username(params[:username]) == nil
    @invalid_username = %Q{This is not a valid username.}
    @valid_input = false
  elsif name_in_database?(params[:username])
    @invalid_username = %Q{This user already exists.}
    @valid_input = false
  else
    @invalid_username = ''
  end

  if validate_password(params[:password]) == nil
    @invalid_password = %Q{This is not a valid password.}
    @valid_input = false
  else
    @invalid_password = ''
  end

  if params[:password] != params[:verify]
    @invalid_verify = %Q{The passwords do not match.}
    @valid_input = false
  else
    @invalid_verify = ''
  end

  if (params[:email] != '') && (validate_email(params[:email]) == nil)
    @invalid_email = %Q{This is not a valid email address.}
    @valid_input = false
  else
    @invalid_email = ''
  end

  if @valid_input == true
    password_hash = make_password_hash(params[:username], params[:password], make_salt)
    session[:username] = make_secure_value params[:username]
    entry = Password.create(:username => session[:username], :password => password_hash)
    session[:valid_password] = true
    redirect '/welcome'
  else
    write_form(@invalid_username, @invalid_password, @invalid_verify, @invalid_email)
  end
end

get '/login' do
  haml :login
end

post '/login' do
  @username = params[:username]
  @password = params[:password]
  session[:valid_password] = false
  if name_and_password_in_database?(@username, @password)
    session[:username] = make_secure_value @username
    @invalid_login = ''
    session[:valid_password] = true
    redirect '/welcome'
  else
    @invalid_login = 'Invalid login'
  end
  haml :login
end

get '/welcome' do
  if session[:username]
    @username = get_value_from_hash session[:username]
    session[:username] = nil
    haml :welcome
  else
    $start_time = current_time
    redirect '/blog'
  end
end

get '/logout' do
  session[:valid_password] = nil
  session.clear
  newest_post.subject = ''
  newest_post.content = ''
  redirect '/login'
end

get '/blog' do
  render_blogs(newest_post.subject, newest_post.content, params[:error])
end

get '/.json' do
  content_type :json
  blogs_listing = Post.all(:order => :created.desc, :limit => 10)
  blogs_listing.to_json
end

post '/newpost' do
  newest_post.subject = params[:subject]
  newest_post.content = params[:content]
  error = ''

  if newest_post.subject.length > 0 && newest_post.content.length > 0
    post = Post.create(:subject => params[:subject], :content => params[:content])
    get_top_ten_blogs(true)
    $post_start_time = current_time
    redirect '/blog/' + post.id.to_s
  else
    error = 'Add missing subject and/or content!'
    render_blogs(params[:subject], params[:content], error)
  end
end

get %r{/blog/(?<permalink>[\d]+)(?<format>[\.json]*)} do
  perma_post = get_perma_post(params[:permalink])

  if perma_post == nil
    render_blogs('', '', 'That post does not exist!!')
  elsif params[:format] == '.json'
    content_type :json
    perma_post.to_json
  else
    @age = current_time - $post_start_time
    haml :post, :locals => {:subject => perma_post.subject, :content => perma_post.content}
  end
end

get '/flush' do
  $start_time = current_time
  $post_start_time = $start_time
  $CACHE.flush_all
  redirect '/blog'
end
