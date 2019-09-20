require 'minitest/autorun'
require 'vcert'


class VcertTest < Minitest::Test
  def test_request
    conn = Vcert::CloudConnection.new '', ''
    assert_equal "ololo",
      conn.request
  end
end
