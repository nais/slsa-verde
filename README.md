# slsa-verde

## Development

### Setup

Pre-requisites:

Copy the `.env.example` file from [here](hack/.env.sample)
to the root of the project and rename it to `.env` and fill in the required environment variables.
Example is listed in the `.env.example` file.

To start the development environment, run the following command;

```bash
make dtrack-up
```

wait for dp to be ready and run;

```bash
make local
```

Navigate to the cluster you are interested to work with, slsa-verde will now start to fetch data from the cluster.
And fill the local database with the data.

You can now access the instance of Dependant Track by navigating to `http://localhost:9010` in your browser.
If it is fresh start, you will need to create a user to be able to login. Navigate to `http://localhost:9010`
Login with admin user and password `admin` and create a new password matching the password in your `.env` file.
Navigate to Administration -> Access Management -> Teams -> Administrators and click the plus sign to add api_key to the team.
slsa-verde will now be able to fetch data from the cluster.
