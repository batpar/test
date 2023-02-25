{
  title: 'Amazon SQS',

  connection: {
    fields: [
      { name: 'api_key',
        label: 'Access key ID',
        optional: false,
        control_type: 'password',
        hint: 'Go to <b>AWS account name</b> > <b>My Security ' \
          'Credentials</b> > <b>Users</b>. Get API key from ' \
          'existing user or create new user.' },
      { name: 'secret_key',
        label: 'Secret access key',
        optional: false,
        control_type: 'password',
        hint: 'Go to <b>AWS account name</b> > <b>My Security ' \
          'Credentials</b> > <b>Users</b>. Get secret key from' \
          ' existing user or create new user.' },
      { name: 'region',
        label: 'Region',
        optional: false,
        hint: 'Your SQS queue region, defined in the queue ARN. If your queue ARN is ' \
              '<b>  arn:aws:sqs:us-east-1:641923904298:gabriel_standard_q</b>, ' \
              'use us-east-1 as the region.' },
      { name: 'version', type: 'string', control_type: 'select',
        pick_list: [
          ['2012-11-05', '2012-11-05']
        ] },
      { name: 'service', type: 'string', control_type: 'select',
        pick_list: [
          %w[SQS sqs],
          ['SQS-FIPS', 'sqs-fips']
        ],
        hint: 'Your SQS queue service, defined in the queue ARN. If your queue ARN is ' \
              '<b>  arn:aws:sqs-fips:us-east-1:641923904298:gabriel_standard_q</b>, ' \
              'use sqs-fips as the service.' }
    ],

    authorization: {
      type: 'custom',
      credentials: lambda do |_|
      end
    }
  },

  test: lambda do |connection|
    # List Queues
    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ListQueues.html

    payload = "Action=ListQueues&Version=#{connection['version']}"

    signature = call(:generate_aws_signature,
                     api_key: connection['api_key'],
                     secret_key: connection['secret_key'],
                     region: connection['region'],
                     service: connection['service'],
                     path: '/',
                     http_method: 'POST',
                     params: '',
                     payload: payload)

    url = signature[0]
    headers = signature[1]

    post(url).headers(headers).request_body(payload)
  end,

  methods: {
    generate_aws_signature: lambda do |input|
      api_key = input[:api_key]
      secret_key = input[:secret_key]
      service = input[:service]
      region = input[:region]
      path = input[:path]
      http_method = input[:http_method]
      params = input[:params] || ''
      payload = input[:payload] || ''
      aws_header = input[:aws_header] || {}

      time = now.to_time.utc.strftime('%Y%m%dT%H%M%SZ')
      date = time.split('T').first
      protocol = 'https'
      host = "#{service}.#{region}.amazonaws.com"
      param_str = params.to_param
      aws_header = aws_header.merge('Host' => host,
                                    'Content-Type' => 'application/x-www-form-urlencoded',
                                    'X-Amz-Date' => time)
      url = "#{protocol}://#{host}#{path}"
      url = url + "?#{param_str}" if params.present?
      sign_algo = 'AWS4-HMAC-SHA256'

      # Creating canonical request
      c_header = aws_header.sort.map { |k, v| "#{k.downcase}:#{v}" }.join("\n") + "\n"
      c_header_keys = aws_header.sort.map { |k, _| k.downcase }.join(';')
      payload_hash = payload.encode_sha256.encode_hex
      param_str = params.present? ? params.to_param : ''
      step1 = [http_method, path, param_str, c_header,
               c_header_keys, payload_hash].join("\n").encode_sha256.encode_hex

      # creating a string to sign
      scope = [date, region, service, 'aws4_request'].join('/')
      string_sign = [sign_algo, time, scope, step1].join("\n")

      # calculating signature
      k_date = date.hmac_sha256("AWS4#{secret_key}")
      k_region = region.hmac_sha256(k_date)
      k_service = service.hmac_sha256(k_region)
      k_signing = 'aws4_request'.hmac_sha256(k_service)
      signature = string_sign.hmac_sha256(k_signing).encode_hex

      auth_header = "#{sign_algo} Credential=#{api_key}/#{scope.strip}, SignedHeaders=#{c_header_keys}, Signature=#{signature}"
      headers = aws_header.merge('Authorization' => auth_header)
      [url, headers]
    end,

    input_parser: lambda do |input|
      hash = {}
      %w[MessageAttribute MessageSystemAttribute].each do |field|
        input.delete(field)&.each_with_index do |item, index|
          hash["#{field}.#{index + 1}.Name"] = item['key']
          if item['type'] == 'Binary'
            hash["#{field}.#{index + 1}.Value.BinaryValue"] = item['value']
          else
            hash["#{field}.#{index + 1}.Value.StringValue"] = item['value']
          end
          hash["#{field}.#{index + 1}.Value.DataType"] = item['type']
        end
      end
      input['AttributeName'] = input['AttributeName']&.split(',')
      input.delete('AttributeName')&.each_with_index do |item, index|
        hash["AttributeName.#{index + 1}"] = item
      end
      input.delete('MessageAttributeName')&.each_with_index do |item, index|
        hash["MessageAttributeName.#{index + 1}"] = item['value']
      end
      input = input.merge(hash)
    end,

    receive_message_schema: lambda do
      [
        { name: 'Attributes',
          type: 'array', of: 'object',
          properties: [
            { name: 'Name' },
            { name: 'Value' }
          ] },
        { name: 'Body' },
        { name: 'MD5OfBody' },
        { name: 'MD5OfMessageAttributes' },
        { name: 'MessageAttributes',
          type: 'array', of: 'object',
          properties: [
            { name: 'Name' },
            { name: 'Value', type: 'object',
              properties: [
                { name: 'BinaryListValues' },
                { name: 'BinaryValue' },
                { name: 'DataType' },
                { name: 'StringListValues' },
                { name: 'StringValue' }
              ] }
          ] },
        { name: 'MessageId' },
        { name: 'ReceiptHandle' }
      ]
    end
  },

  object_definitions: {

    delete_schema: {
      fields: lambda do |_connection|
        [
          {
            name: 'QueueUrl',
            label: 'Queue URL',
            optional: false,
            control_type: 'select',
            pick_list: 'queues',
            toggle_hint: 'Select from list',
            toggle_field: {
              name: 'QueueUrl',
              label: 'Queue URL',
              type: :string,
              control_type: 'text',
              optional: false,
              toggle_hint: 'Enter Queue URL',
              hint: 'Go to SQS Management Console and copy the Queue URL.'
            },
            hint: 'The URL of the Amazon SQS queue to which a message is sent.'
          },
          {
            name: 'ReceiptHandle',
            hint: 'The receipt handle associated with the message to delete.',
            optional: false
          },
          { name: 'DeleteMessageResponse',
            type: 'object',
            properties: [
              { name: 'ResponseMetadata',
                type: 'object',
                properties: [
                  { name: 'RequestId' }
                ] }
            ] }
        ]
      end
    },

    send_message_input: {
      fields: lambda do |_connection|
        [
          {
            name: 'QueueUrl',
            label: 'Queue URL',
            optional: false,
            control_type: 'select',
            pick_list: 'queues',
            toggle_hint: 'Select from list',
            toggle_field: {
              name: 'QueueUrl',
              label: 'Queue URL',
              type: :string,
              control_type: 'text',
              optional: false,
              toggle_hint: 'Enter Queue URL',
              hint: 'Go to SQS Management Console and copy the Queue URL.'
            },
            hint: 'The URL of the Amazon SQS queue to which a message is sent.'
          },
          {
            name: 'MessageBody',
            label: 'Message Body',
            optional: false,
            hint: 'The message to send. The maximum string size is 256 KB.'
          },
          {
            name: 'MessageDeduplicationId',
            label: 'Message Deduplication ID',
            optional: true,
            hint: 'This parameter applies only to FIFO (first-in-first-out) queues. ' \
                  'The token used for deduplication of sent messages. If a message ' \
                  'with a particular MessageDeduplicationId is sent successfully, ' \
                  'any messages sent with the same MessageDeduplicationId are accepted' \
                  "successfully but aren't delivered during the 5-minute deduplication interval."
          },
          {
            name: 'MessageGroupId',
            label: 'Message group ID',
            optional: true,
            hint: 'This parameter applies only to FIFO (first-in-first-out) queues.' \
                  'The tag that specifies that a message belongs to a specific message ' \
                  'group. Messages that belong to the same message group are ' \
                  'processed in a FIFO manner'
          },
          { name: 'MessageAttribute', type: 'array', of: 'object',
            item_label: 'Message attribute',
            add_item_label: 'Add message attribute',
            empty_list_title: 'Message attribute list is empty',
            properties: [
              { name: 'key' },
              { name: 'value' },
              { name: 'type', type: 'string', control_type: 'select',
                optional: false,
                pick_list: 'data_type', toggle_hint: 'Select from list',
                hint: 'The message attribute data type. ' \
                      "Supported types include 'String', 'Number', and 'Binary'.",
                toggle_field: {
                  name: 'type', label: 'Type',
                  type: 'string', control_type: 'text',
                  optional: false,
                  toggle_hint: 'Use custom  value',
                  hint: "Allowed values are 'String', 'Number' or 'Binary'."
                } }
            ] },
          { name: 'MessageSystemAttribute', type: 'array', of: 'object',
            item_label: 'Message system attribute',
            add_item_label: 'Add message system attribute',
            empty_list_title: 'Message system attribute list is empty',
            properties: [
              { name: 'key' },
              { name: 'value' },
              { name: 'type', type: 'string', control_type: 'select',
                optional: false,
                pick_list: 'data_type', toggle_hint: 'Select from list',
                hint: 'The message system attribute data type. ' \
                      "Supported types include 'String', 'Number', and 'Binary'.",
                toggle_field: {
                  name: 'type', label: 'Type',
                  type: 'string', control_type: 'text',
                  optional: false,
                  toggle_hint: 'Use custom  value',
                  hint: "Allowed values are 'String', 'Number' or 'Binary'."
                } }
            ] }
        ]
      end
    },

    send_message_output: {
      fields: lambda do |_connection|
        [
          { name: 'SendMessageResponse',
            type: 'object',
            properties: [
              { name: 'ResponseMetadata',
                type: 'object',
                properties: [
                  { name: 'RequestId' }
                ] },
              { name: 'SendMessageResult',
                type: 'object',
                properties: [
                  { name: 'MD5OfMessageAttributes' },
                  { name: 'MD5OfMessageBody' },
                  { name: 'MD5OfMessageSystemAttributes' },
                  { name: 'MessageId' },
                  { name: 'SequenceNumber' }
                ] }
            ] }
        ]
      end
    },

    receive_message_input: {
      fields: lambda do |_connection|
        [
          { name: 'AttributeName',
            control_type: 'multiselect',
            delimiter: ',',
            pick_list: 'attribute_name',
            hint: 'A list of attributes that need to be returned along with each message.' },
          { name: 'MessageAttributeName', type: 'array', of: 'object',
            properties: [
              { name: 'value' }
            ] },
          { name: 'MaxNumberOfMessages', type: 'integer',
            default: 1,
            render_input: 'integer_conversion',
            parse_output: 'integer_conversion',
            hint: 'The maximum number of messages to return. Amazon SQS never ' \
                  'returns more messages than this value (however, fewer ' \
                  'messages might be returned). Valid values: 1 to 10. Default: 1.' },
          { name: 'QueueUrl',
            label: 'Queue URL',
            optional: false,
            control_type: 'select',
            pick_list: 'queues',
            toggle_hint: 'Select from list',
            toggle_field: {
              name: 'QueueUrl',
              label: 'Queue URL',
              type: :string,
              control_type: 'text',
              optional: false,
              toggle_hint: 'Enter Queue URL',
              hint: 'Go to SQS Management Console and copy the Queue URL.'
            },
            hint: 'The URL of the Amazon SQS queue to which a message is sent.' },
          { name: 'VisibilityTimeout', type: 'integer',
            render_input: 'integer_conversion',
            parse_output: 'integer_conversion',
            hint: 'The duration (in seconds) that the received messages are ' \
                  'hidden from subsequent retrieve requests after being ' \
                  'retrieved by a ReceiveMessage request.' },
          { name: 'WaitTimeSeconds', type: 'integer',
            render_input: 'integer_conversion',
            parse_output: 'integer_conversion',
            hint: 'The duration (in seconds) for which the call waits for a ' \
                  'message to arrive in the queue before returning. If a ' \
                  'message is available, the call returns sooner than WaitTimeSeconds. ' \
                  'If no messages are available and the wait time expires, ' \
                  'the call returns successfully with an empty list of messages.' }
        ]
      end
    },

    receive_message_output: {
      fields: lambda do |_connection|
        [
          { name: 'ReceiveMessageResponse', type: 'object',
            properties: [
              { name: 'ReceiveMessageResult', type: 'object',
                properties: [
                  { name: 'messages', type: 'array', of: 'object',
                    properties: call('receive_message_schema') }
                ] },
              { name: 'ResponseMetadata', type: 'object',
                properties: [
                  { name: 'RequestId' }
                ] }
            ] }
        ]
      end
    },

    triggers_output_schema: {
      fields: lambda do |_connection|
        call('receive_message_schema')
      end
    }
  },

  actions: {
    send_message: {
      title: 'Send message',
      description: "Send a <span class='provider'>Message " \
                   ' </span> to the specified queue using ' \
                   "<span class='provider'>Amazon SQS</span>",
      help: {
        body: 'Delivers a message to the specified queue.',
        learn_more_url: 'https://docs.aws.amazon.com/en_pv/AWSSimpleQueueService/' \
                        'latest/APIReference/API_SendMessage.html',
        learn_more_text: 'Amazon SQS API Documentation'
      },
      input_fields: lambda do |object_definitions|
        object_definitions['send_message_input']
      end,

      execute: lambda do |connection, input|
        # Action metadata
        input['Action'] = 'SendMessage'
        input['Version'] = connection['version']
        input = call('input_parser', input)
        # Format input according to API spec
        input = input.encode_www_form

        signature = call(:generate_aws_signature,
                         api_key: connection['api_key'],
                         secret_key: connection['secret_key'],
                         region: connection['region'],
                         service: connection['service'],
                         path: '/',
                         http_method: 'POST',
                         params: '',
                         payload: input)

        url = signature[0]
        headers = signature[1]

        post(url).headers(headers).request_body(input).
          after_error_response(//) do |_code, body, _header, message|
          error("#{message}: #{body}")
        end
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['send_message_output']
      end,

      sample_output: lambda do
        {
          'SendMessageResponse' => {
            'ResponseMetadata' => {
              'RequestId' => '27daac76-34dd-47df-bd01-1f6e873584a0'
            },
            'SendMessageResult' => {
              'MD5OfMessageBody' => 'fafb00f5732ab283681e124bf8747ed1',
              'MD5OfMessageAttributes' => '3ae8f24a165a8cedc005670c81a27295',
              'MessageId' => '5fea7756-0ea4-451a-a703-a558b933e274'
            }
          }
        }
      end
    },

    delete_message: {
      title: 'Delete message',
      description: "Delete a <span class='provider'>Message" \
                   ' </span> from ' \
                   "<span class='provider'>Amazon SQS</span>",
      help: {
        body: 'Deletes the specified message from the specified queue.',
        learn_more_url: 'https://docs.aws.amazon.com/en_pv/AWSSimpleQueueService/ ' \
                        'latest/APIReference/API_DeleteMessage.html',
        learn_more_text: 'Amazon SQS API Documentation'
      },
      input_fields: lambda do |object_definitions|
        object_definitions['delete_schema'].ignored('DeleteMessageResponse')
      end,

      execute: lambda do |connection, input|
        # Action metadata
        input['Action'] = 'DeleteMessage'
        input['Version'] = connection['version']
        path = '/' + input['QueueUrl'].split('amazonaws.com/').last

        # Remove fields which should not go into the signature generation
        input = input.reject { |k, _| %w[QueueUrl].include?(k) }

        signature = call(:generate_aws_signature,
                         api_key: connection['api_key'],
                         secret_key: connection['secret_key'],
                         region: connection['region'],
                         service: connection['service'],
                         path: path,
                         http_method: 'POST',
                         params: '',
                         payload: input.encode_www_form)

        url = signature[0]
        headers = signature[1]

        post(url).headers(headers).request_body(input).
          after_error_response(//) do |_code, body, _header, message|
          error("#{message}: #{body}")
        end
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['delete_schema'].only('DeleteMessageResponse')
      end,

      sample_output: lambda do
        {
          'DeleteMessageResponse' => {
            'ResponseMetadata' => {
              'RequestId' => 'b5293cb5-d306-4a17-9048-b263635abe42'
            }
          }
        }
      end
    },

    receive_message: {
      title: 'Receive message',
      description: "Receive <span class='provider'>Message " \
                   ' </span> from the specified queue using ' \
                   "<span class='provider'>Amazon SQS</span>",
      help: {
        body: 'Receive messages from the specified queue.',
        learn_more_url: 'https://docs.aws.amazon.com/en_pv/AWSSimpleQueueService/' \
                        'latest/APIReference/API_ReceiveMessage.html',
        learn_more_text: 'Amazon SQS API Documentation'
      },
      input_fields: lambda do |object_definitions|
        object_definitions['receive_message_input']
      end,

      execute: lambda do |connection, input|
        # Action metadata
        input['Action'] = 'ReceiveMessage'
        input['Version'] = connection['version']
        input = call('input_parser', input)

        # Format input according to API spec
        input = input.encode_www_form

        signature = call(:generate_aws_signature,
                         api_key: connection['api_key'],
                         secret_key: connection['secret_key'],
                         region: connection['region'],
                         service: connection['service'],
                         path: '/',
                         http_method: 'POST',
                         params: '',
                         payload: input)

        url = signature[0]
        headers = signature[1]

        post(url).headers(headers).request_body(input).
          after_error_response(//) do |_code, body, _header, message|
          error("#{message}: #{body}")
        end
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['receive_message_output']
      end,

      sample_output: lambda do
        { ReceiveMessageResponse:
          { ReceiveMessageResult:
            { messages:
              [
                { Attributes:
                  [
                    { Name: 'SenderId',
                      Value: 'AIDAZK5NFOMVJOPHMFLNU' }
                  ],
                  Body: 'Connector testing',
                  MD5OfBody: 'd703b9f42c390be5c461599ef36cae44',
                  MD5OfMessageAttributes: 'dda6df21a0bb399a9959b6fe938b1925',
                  MessageAttributes:
                  [{ Name: 'Age',
                     Value: {
                       DataType: 'Number',
                       StringValue: '18'
                     } }],
                  MessageId: '205ab279-ddec-4249-9654-35051cd39ce3' }
              ] },
            ResponseMetadata: { RequestId: '585b6395-dd2b-5be5-b18b-34fb5fbe47b2' } } }
      end
    }
  },

  triggers: {
    new_message: {
      title: 'New Message',
      help: 'Trigger deduplication is checked on Message ReceiptHandle. ' \
            'Therefore you might receive duplicate messages if you do ' \
            'not delete received messages.',

      input_fields: lambda do |object_definitions|
        [
          {
            name: 'auto_delete',
            label: 'Automatically delete message',
            type: :boolean,
            control_type: :checkbox,
            hint: 'Delete messages once it is received',
            sticky: false,
            optional: true
          }
        ].concat(object_definitions['delete_schema'].only('QueueUrl'))
      end,

      poll: lambda do |connection, input, _last_updated_since|
        page_size = 10

        # Receive Messages
        payload = "Action=ReceiveMessage&Version=#{connection['version']}&MessageAttributeName=All&AttributeName=All&MaxNumberOfMessages=#{page_size}"
        path = '/' + input['QueueUrl'].split('amazonaws.com/').last

        signature = call(:generate_aws_signature,
                         api_key: connection['api_key'],
                         secret_key: connection['secret_key'],
                         region: connection['region'],
                         service: connection['service'],
                         path: path,
                         http_method: 'POST',
                         params: '',
                         payload: payload)

        url = signature[0]
        headers = signature[1]

        messages = post(url).headers(headers).request_body(payload).
                     after_error_response(//) do |_code, body, _header, message|
          error("#{message}: #{body}")
        end

        messages = messages.dig('ReceiveMessageResponse', 'ReceiveMessageResult', 'messages') || []

        # Delete Messages in Queue
        if input['auto_delete'].is_true?
          messages.each do |msg|
            payload = {
              'Action': 'DeleteMessage',
              'Version': connection['version'],
              'ReceiptHandle': msg['ReceiptHandle']
            }.encode_www_form

            signature = call(:generate_aws_signature,
                             api_key: connection['api_key'],
                             secret_key: connection['secret_key'],
                             region: connection['region'],
                             service: connection['service'],
                             path: path,
                             http_method: 'POST',
                             params: '',
                             payload: payload)

            url = signature[0]
            headers = signature[1]

            res = post(url).
                    headers(headers).
                    request_body(payload).
                    after_error_response(//) do |_code, body, _header, message|
              error("#{message}: #{body}")
            end

            puts res # Bypass lazy evaluation
          end
        end

        {
          events: messages,
          next_poll: nil,
          # AWS API quirk:
          # MaxNumberOfMessages parameter is simply the max msgs AWS chooses to repond but it can be anything from 0 to page_size
          # Therefore, can_poll_more is possible even if size < page_size
          # Nonetheless, we max out page_size to optimize API calls.
          # See: https://docs.aws.amazon.com/en_pv/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
          can_poll_more: messages.present?
        }
      end,

      dedup: lambda do |event|
        event['ReceiptHandle']
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['triggers_output_schema']
      end,

      sample_output: lambda do
        { Attributes:
          [
            { Name: 'SenderId',
              Value: 'AIDAZK5NFOMVJOPHMFLNU' }
          ],
          Body: 'Connector testing',
          MD5OfBody: 'd703b9f42c390be5c461599ef36cae44',
          MD5OfMessageAttributes: 'dda6df21a0bb399a9959b6fe938b1925',
          MessageAttributes:
          [{ Name: 'Age',
             Value: {
               DataType: 'Number',
               StringValue: '18'
             } }],
          MessageId: '205ab279-ddec-4249-9654-35051cd39ce3' }
      end
    }
  },

  pick_lists: {
    queues: lambda do |connection|
      # List Queues
      payload = 'Action=ListQueues&Version=2012-11-05'

      signature = call(:generate_aws_signature,
                       api_key: connection['api_key'],
                       secret_key: connection['secret_key'],
                       region: connection['region'],
                       service: connection['service'],
                       path: '/',
                       http_method: 'POST',
                       params: '',
                       payload: payload)

      url = signature[0]
      headers = signature[1]

      queues = post(url).
                 headers(headers).
                 request_body(payload).
                 after_error_response(//) do |_code, body, _header, message|
        error("#{message}: #{body}")
      end

      queues.dig('ListQueuesResponse', 'ListQueuesResult', 'queueUrls').map do |q|
        [q.split('/').last, q]
      end
    end,

    attribute_name: lambda do
      %w[All Policy VisibilityTimeout MaximumMessageSize MessageRetentionPeriod
         ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible
         CreatedTimestamp LastModifiedTimestamp QueueArn
         ApproximateNumberOfMessagesDelayed DelaySeconds
         ReceiveMessageWaitTimeSeconds RedrivePolicy FifoQueue
         ContentBasedDeduplication KmsMasterKeyId
         KmsDataKeyReusePeriodSeconds].map { |key| [key.labelize, key] }
    end,

    data_type: lambda do
      %w[String Number Binary].map { |key| [key, key] }
    end
  }
}
