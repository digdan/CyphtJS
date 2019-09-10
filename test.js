var cypht = require('./build/index');

let sizeTestCount = 0;

function sizeTest(message, keys) {
  const crypted = cypht.encypht(message, keys.publicKey);
  const decrypted = cypht.decypht(crypted, keys.privateKey).toString();
  sizeTestCount++;
  const change = Math.round((crypted.length / message.length) * 100);
  console.log('Message Size Test #', sizeTestCount ,'From', message.length, 'bytes to', crypted.length,'bytes. A', change,'% change. Message : ',decrypted);
}


console.log('Generating keys');
const started = Date.now();
cypht.generateKeys().then( keys => {
  console.log('Keys generated in', (Date.now() - started), 'ms');
  console.log('Private Key', keys.privateKey.exportRaw());
  console.log('Public Key', keys.publicKey.exportRaw());
  const signPayload = 1337;
  console.log('Signing test. Payload:', signPayload);
  const signed = keys.privateKey.sign(signPayload);
  console.log('Private key signed:', signed);
  console.log('Public key verified:', keys.publicKey.verify(signed , signPayload));
  console.log('')
  sizeTest('We strike at dawn', keys);
  sizeTest('The fruitsalad was poisoned', keys);
  sizeTest('Go confidently in the direction of your dreams. Live the life you have imagined.', keys);
  sizeTest(JSON.stringify([
  {
    "_id": "5d75939e411967245e796c65",
    "index": 0,
    "guid": "c277fd18-d8e0-4b70-bcc8-069bf22b4ecb",
    "isActive": false,
    "balance": "$1,081.62",
    "picture": "http://placehold.it/32x32",
    "age": 25,
    "eyeColor": "green",
    "name": "Crane Christensen",
    "gender": "male",
    "company": "VALPREAL",
    "email": "cranechristensen@valpreal.com",
    "phone": "+1 (828) 527-2490",
    "address": "515 Division Place, Caln, North Dakota, 4681",
    "about": "Occaecat aute eu exercitation enim labore duis labore reprehenderit consectetur reprehenderit nostrud. Eiusmod ex proident veniam ipsum eiusmod est exercitation aliquip fugiat tempor sint ad ex. Dolor do quis sint dolor ut. Aliqua duis Lorem ullamco esse sunt ad sint ea. Ullamco dolore quis id minim aliqua consectetur ea duis. Voluptate enim nostrud eu labore elit quis mollit voluptate. Consectetur laboris incididunt dolore eiusmod non ullamco cillum amet.\r\n",
    "registered": "2016-10-15T01:17:42 +07:00",
    "latitude": -24.939777,
    "longitude": 140.816693,
    "tags": [
      "aliquip",
      "elit",
      "id",
      "dolor",
      "elit",
      "adipisicing",
      "occaecat"
    ],
    "friends": [
      {
        "id": 0,
        "name": "Dyer Franks"
      },
      {
        "id": 1,
        "name": "Humphrey Hughes"
      },
      {
        "id": 2,
        "name": "Britt Harrell"
      }
    ],
    "greeting": "Hello, Crane Christensen! You have 2 unread messages.",
    "favoriteFruit": "banana"
  },
  {
    "_id": "5d75939e107c31ae64669724",
    "index": 1,
    "guid": "e5b91952-4c17-4c04-bc88-cb1c49832c33",
    "isActive": false,
    "balance": "$3,984.36",
    "picture": "http://placehold.it/32x32",
    "age": 24,
    "eyeColor": "blue",
    "name": "Jordan Davenport",
    "gender": "female",
    "company": "CALCU",
    "email": "jordandavenport@calcu.com",
    "phone": "+1 (924) 547-3029",
    "address": "420 Devon Avenue, Hickory, North Carolina, 468",
    "about": "Ex aliquip consectetur exercitation non esse cillum nostrud nulla nulla occaecat. Veniam id duis aute irure adipisicing nisi cillum non veniam eu consequat ex duis. Excepteur voluptate ipsum minim sit aute aliqua proident sit eiusmod ea fugiat consectetur. Veniam dolore aliqua nisi enim eu velit tempor anim mollit cupidatat laboris ipsum tempor.\r\n",
    "registered": "2017-04-29T02:24:53 +07:00",
    "latitude": 53.89098,
    "longitude": 44.938965,
    "tags": [
      "mollit",
      "non",
      "velit",
      "dolore",
      "consectetur",
      "officia",
      "ex"
    ],
    "friends": [
      {
        "id": 0,
        "name": "Hardin Hensley"
      },
      {
        "id": 1,
        "name": "Howard Stuart"
      },
      {
        "id": 2,
        "name": "Kerry Roberson"
      }
    ],
    "greeting": "Hello, Jordan Davenport! You have 7 unread messages.",
    "favoriteFruit": "strawberry"
  },
  {
    "_id": "5d75939e13c87acc2e02b6d7",
    "index": 2,
    "guid": "6fac3beb-b371-47de-a353-6e6ffa97af16",
    "isActive": true,
    "balance": "$3,943.83",
    "picture": "http://placehold.it/32x32",
    "age": 40,
    "eyeColor": "green",
    "name": "Jean Sandoval",
    "gender": "female",
    "company": "QUARMONY",
    "email": "jeansandoval@quarmony.com",
    "phone": "+1 (909) 491-2328",
    "address": "838 Arkansas Drive, Vincent, Louisiana, 5048",
    "about": "Lorem laborum amet reprehenderit anim ea ex qui duis elit ullamco proident et. Irure non est occaecat ullamco sunt reprehenderit anim magna cillum id officia. Aute dolore irure laborum fugiat veniam ea do occaecat et sunt nisi velit incididunt pariatur. Ipsum voluptate irure esse ad. Ea esse ut ullamco aliqua nisi velit. Id ut magna id est non magna tempor incididunt quis pariatur. Consequat excepteur anim culpa ea enim proident esse nisi voluptate enim ad amet elit minim.\r\n",
    "registered": "2017-04-01T03:39:43 +07:00",
    "latitude": -60.163792,
    "longitude": 94.696161,
    "tags": [
      "amet",
      "quis",
      "adipisicing",
      "commodo",
      "est",
      "aliquip",
      "culpa"
    ],
    "friends": [
      {
        "id": 0,
        "name": "Nadine Smith"
      },
      {
        "id": 1,
        "name": "Ellis Juarez"
      },
      {
        "id": 2,
        "name": "Leach Woodard"
      }
    ],
    "greeting": "Hello, Jean Sandoval! You have 2 unread messages.",
    "favoriteFruit": "banana"
  },
  {
    "_id": "5d75939e86abdaa9166da4c3",
    "index": 3,
    "guid": "c2d5a141-e629-4a35-b1b8-4f9eb600dce8",
    "isActive": true,
    "balance": "$1,946.21",
    "picture": "http://placehold.it/32x32",
    "age": 38,
    "eyeColor": "green",
    "name": "Deann Austin",
    "gender": "female",
    "company": "OMNIGOG",
    "email": "deannaustin@omnigog.com",
    "phone": "+1 (935) 584-2851",
    "address": "211 Lacon Court, Brazos, Florida, 4462",
    "about": "Excepteur reprehenderit exercitation nisi sint ad adipisicing reprehenderit deserunt consectetur do nisi. Esse ullamco cillum Lorem ipsum sit nulla Lorem tempor. Reprehenderit dolor incididunt labore dolor minim laborum veniam voluptate enim nulla id commodo dolor cillum. Minim do pariatur labore officia sit dolore non laborum ea qui labore pariatur excepteur. Lorem est enim et mollit. Ipsum incididunt duis enim magna quis exercitation sunt nostrud do.\r\n",
    "registered": "2019-05-17T05:03:01 +07:00",
    "latitude": -87.946292,
    "longitude": 13.234039,
    "tags": [
      "mollit",
      "aute",
      "ea",
      "irure",
      "minim",
      "ex",
      "reprehenderit"
    ],
    "friends": [
      {
        "id": 0,
        "name": "Lesley Frank"
      },
      {
        "id": 1,
        "name": "Bonita Hogan"
      },
      {
        "id": 2,
        "name": "Gray Daniel"
      }
    ],
    "greeting": "Hello, Deann Austin! You have 1 unread messages.",
    "favoriteFruit": "banana"
  },
  {
    "_id": "5d75939e624debc195fb3159",
    "index": 4,
    "guid": "443eefd1-205b-498c-874e-e778e89d0ee1",
    "isActive": true,
    "balance": "$1,136.52",
    "picture": "http://placehold.it/32x32",
    "age": 40,
    "eyeColor": "green",
    "name": "Larson Oconnor",
    "gender": "male",
    "company": "ACRUEX",
    "email": "larsonoconnor@acruex.com",
    "phone": "+1 (953) 544-3779",
    "address": "615 Schroeders Avenue, Woodburn, New York, 8397",
    "about": "Excepteur non fugiat dolor exercitation duis excepteur qui. Id sint enim sint minim ex sint voluptate id ex ut ullamco nisi anim officia. Tempor quis sint laboris nisi proident commodo adipisicing irure velit labore aute. Id aliquip eiusmod velit mollit nisi ad ipsum tempor enim ipsum. Pariatur consequat labore elit sit deserunt ea. Aute sint commodo deserunt occaecat.\r\n",
    "registered": "2015-02-09T10:31:06 +08:00",
    "latitude": 10.548484,
    "longitude": -28.784187,
    "tags": [
      "in",
      "exercitation",
      "culpa",
      "velit",
      "minim",
      "anim",
      "quis"
    ],
    "friends": [
      {
        "id": 0,
        "name": "Ramsey Mccormick"
      },
      {
        "id": 1,
        "name": "June Alexander"
      },
      {
        "id": 2,
        "name": "Guerrero Justice"
      }
    ],
    "greeting": "Hello, Larson Oconnor! You have 4 unread messages.",
    "favoriteFruit": "strawberry"
  },
  {
    "_id": "5d75939ebfb75d95fa9babe0",
    "index": 5,
    "guid": "5bbef819-9407-4200-90c5-e8afd8a7342c",
    "isActive": false,
    "balance": "$2,280.18",
    "picture": "http://placehold.it/32x32",
    "age": 40,
    "eyeColor": "blue",
    "name": "Francis Wagner",
    "gender": "female",
    "company": "QUILM",
    "email": "franciswagner@quilm.com",
    "phone": "+1 (826) 574-2929",
    "address": "498 Kings Hwy, Richmond, South Carolina, 343",
    "about": "Anim do est ea ea fugiat laboris velit nulla in consequat. Ipsum Lorem officia aliquip ut enim sit esse deserunt excepteur sint. Ea adipisicing ex nostrud laborum nisi excepteur proident eiusmod reprehenderit in Lorem veniam aliquip exercitation. Id elit dolore officia laborum reprehenderit excepteur irure ipsum laboris. Veniam nisi commodo enim Lorem. Officia sit esse velit tempor deserunt voluptate minim ex exercitation deserunt excepteur mollit deserunt. Adipisicing in reprehenderit commodo id irure dolor labore duis sit.\r\n",
    "registered": "2015-04-17T06:03:52 +07:00",
    "latitude": -74.558118,
    "longitude": 48.207688,
    "tags": [
      "dolore",
      "sint",
      "cillum",
      "et",
      "consequat",
      "aliquip",
      "Lorem"
    ],
    "friends": [
      {
        "id": 0,
        "name": "Delgado Alston"
      },
      {
        "id": 1,
        "name": "Gilbert Hopkins"
      },
      {
        "id": 2,
        "name": "Kayla Colon"
      }
    ],
    "greeting": "Hello, Francis Wagner! You have 1 unread messages.",
    "favoriteFruit": "strawberry"
  }
], null, 4), keys);

});
