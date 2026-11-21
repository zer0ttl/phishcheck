# Email fixtures

- `plain.eml` is a synthetic RFC 822 email with an inert example.com URL.
- `outlook.msg` is a synthetic Outlook message created with Perl's
  `OLE::Storage_Lite`. Its compound document contains a message properties
  stream and UTF-16LE property streams for an `IPM.Note` message. The message
  uses example.com and example.net addresses and contains no attachments.
