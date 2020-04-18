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

def create_file2(len, seed, additional)
  rng = Random.new(seed)
  chars = (0..255).map( &:chr )
  fn = SecureRandom::uuid
  File.open( fn, "w" ) do |f|
    s = Array.new(len){ chars.sample(random:rng) }.join
    f.write( s+additional )
  end
  fn
end


def isSameFile( fn0, fn1 )
  [fn0,fn1].map{ |fn|
    Digest::SHA512::file( fn ).to_s
  }.uniq.size==1
end

def sameByteRatio( fn0, fn1 )
  bytes = [fn0,fn1].map{ |fn|
    File.open( fn, &:read ).bytes
  }
  raise unless bytes[0].size == bytes[1].size
  b = bytes.transpose.drop(8) #先頭8バイトはサイズなので比較しない
  b.count{ |x,y| x==y }.to_f / b.size
end

def pwtest
  src_fn = create_file(10000)
  enc_fns = Array.new(10){ SecureRandom::uuid }
  enc_fns.each.with_index do |enc_fn,ix|
    %x( #{CMD} enc -pw #{ix} -src #{src_fn} -dest #{enc_fn} )
    dec_fn = enc_fn+".decoded"
    %x( #{CMD} dec -pw #{ix} -src #{enc_fn} -dest #{dec_fn} )
    unless isSameFile( dec_fn, src_fn )
      raise "#{dec_fn} is not same to #{src_fn}"
    end
  end
  enc_fns.each.with_index do |enc_fn,ix|
    next if ix==0
    puts( "ix=%d, ratio=%.2f%%" % [ ix, 100.0*sameByteRatio(enc_fns[0], enc_fn)])
  end
end

def almost_same
  fns = (0...10).map{ |v|
    src = create_file2(10000, 0, v.chr)
    [ src, SecureRandom::uuid ]
  }
  puts( "src, ratio=%.2f%%" % [ 100.0*sameByteRatio(fns[0][0], fns[1][0])])
  cm = "des-ecb -S 0 "
  fns.each do |src_fn,enc_fn|
    # %x(openssl #{cm} -e -in #{src_fn} -out #{enc_fn}  -pass pass:pass)
    %x( #{CMD} enc -pw 1 -src #{src_fn} -dest #{enc_fn} )
    dec_fn = enc_fn+".decoded"
    # %x(openssl #{cm} -d -in #{enc_fn} -out #{dec_fn}  -pass pass:pass)
    %x( #{CMD} dec -pw 1 -src #{enc_fn} -dest #{dec_fn} )
    unless isSameFile( dec_fn, src_fn )
      raise "#{dec_fn} is not same to #{src_fn}"
    end
  end
  fns.each.with_index do |(_,enc_fn),ix|
    puts( "ix=%d, ratio=%.2f%%" % [ ix, 100.0*sameByteRatio(fns[0][1], enc_fn)] )
  end
end

def main
  Dir.mktmpdir("test", ".") do |dir|
    Dir.chdir(dir) do
      p Dir.pwd
      pwtest
      almost_same
    end
  end
end

main
