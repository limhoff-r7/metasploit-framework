shared_examples_for 'Metasploit::Framework::Attempt::Creation::Single#attributes' do
  context '[:attempted_at]' do
    subject(:attributes_attempted_at) do
      attributes[:attempted_at]
    end

    it 'uses #attempted_at' do
      expect(attributes_attempted_at).to eq(attempted_at)
    end
  end

  context '[:exploited]' do
    subject(:attributes_exploited) do
      attributes[:exploited]
    end

    it 'uses #exploited' do
      expect(attributes_exploited).to eq(exploited)
    end
  end

  context '[:fail_detail]' do
    subject(:attributes_fail_detail) do
      attributes[:fail_detail]
    end

    it 'uses #fail_detail' do
      expect(attributes_fail_detail).to eq(creation.fail_detail)
    end
  end

  context '[:fail_reason]' do
    subject(:attributes_fail_reason) do
      attributes[:fail_reason]
    end

    it 'uses #fail_reason' do
      expect(attributes_fail_reason).to eq(creation.fail_reason)
    end
  end

  context '[:module_class]' do
    subject(:attributes_module_class) do
      attributes[:module_class]
    end

    it 'uses #cache_exploit_class' do
      expect(attributes_module_class).to eq(cache_exploit_class)
    end
  end

  context '[:username]' do
    subject(:attributes_username) do
      attributes[:username]
    end

    it 'uses #username' do
      expect(attributes_username).to eq(creation.username)
    end
  end

  context '[:vuln]' do
    subject(:attributes_vuln) do
      attributes[:vuln]
    end

    it 'uses #vuln' do
      expect(attributes_vuln).to eq(creation.vuln)
    end
  end
end