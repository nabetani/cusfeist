require "fileutils"
require "tmpdir"
require "securerandom"
require "digest/sha2"

HERE = File.absolute_path(File.split(__FILE__)[0])
CMD = File.join( HERE, "cusfeist" )

srand(0)

def create_file(len)
  chars = (0..255).map( &:chr )
  fn = SecureRandom::uuid
  File.open( fn, "w" ) do |f|
    s = Array.new(len){ chars.sample }.join
    f.write( s )
  end
  fn
end

def isSameFile( fn0, fn1 )
  [fn0,fn1].map{ |fn|
    Digest::SHA512::file( fn ).to_s
  }.uniq.size==1
end

def sameByteRatio( fn0, fn1 )
  b = [fn0,fn1].map{ |fn|
    File.open( fn, &:read ).bytes
  }.transpose
  b.count{ |x,y| x==y }.to_f / b.size
end

def pwtest
  src_fn = create_file(1000)
  enc_fns = Array.new(10){ SecureRandom::uuid }
  enc_fns.each.with_index do |enc_fn,ix|
    %x( #{CMD} enc -pw #{ix} -src #{src_fn} -dest #{enc_fn} )
    puts( %x( md5 #{enc_fn} ) )
    dec_fn = enc_fn+".decoded"
    %x( #{CMD} dec -pw #{ix} -src #{enc_fn} -dest #{dec_fn} )
    unless isSameFile( dec_fn, src_fn )
      raise "#{dec_fn} is not same to #{src_fn}"
    end
  end
  enc_fns.each.with_index do |enc_fn,ix|
    next if ix==0
    puts( "ix=%d, rate=%.2f%%" % [ ix, 100.0*sameByteRatio(enc_fns[0], enc_fn) ])
  end
end

def main
  Dir.mktmpdir("test", ".") do |dir|
    Dir.chdir(dir) do
      p Dir.pwd
      pwtest
    end
  end
end

main
