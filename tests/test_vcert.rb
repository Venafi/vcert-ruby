require 'minitest/autorun'
require 'vcert'


class VcertTest < Minitest::Test
  def test_request
    conn = Vcert::Connection.new 'https://venafi.com', 'ololo'
    assert_equal "ololo",
      conn.request
  end
end
