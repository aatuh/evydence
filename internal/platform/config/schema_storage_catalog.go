package config

var storageDefinitions = []Definition{
	{
		Name:        "EVYDENCE_OBJECT_DIR",
		Kind:        Path,
		MaxBytes:    4096,
		Roles:       API | Worker,
		Default:     "tmp/objects",
		Description: "Local raw payload storage root.",
	},
	{
		Name:        "EVYDENCE_OBJECT_STORE",
		Kind:        Choice,
		Roles:       API | Worker,
		Default:     "filesystem",
		Allowed:     []string{"file", "filesystem", "s3", "minio"},
		Description: "Supported values are `filesystem`, `s3`, and `minio`.",
	},
	{
		Name:               "EVYDENCE_S3_ACCESS_KEY_ID",
		FileOption:         "EVYDENCE_S3_ACCESS_KEY_ID_FILE",
		PreserveWhitespace: true,
		Kind:               Text,
		Roles:              API | Worker,
		Secret:             true,
		Description:        "Store outside source control.",
	},
	{
		Name:        "EVYDENCE_S3_BUCKET",
		Kind:        S3BucketName,
		Roles:       API | Worker,
		Description: "Bucket must already exist. Names use the pinned MinIO SDK's basic S3 bucket grammar after trimming, including its 3 through 63 byte bound.",
	},
	{
		Name:        "EVYDENCE_S3_ENDPOINT",
		Kind:        URL,
		Roles:       API | Worker,
		Description: "Endpoint for S3-compatible object storage.",
	},
	{
		Name:        "EVYDENCE_S3_REGION",
		Kind:        Text,
		Roles:       API | Worker,
		Description: "Optional S3 region.",
	},
	{
		Name:               "EVYDENCE_S3_SECRET_ACCESS_KEY",
		FileOption:         "EVYDENCE_S3_SECRET_ACCESS_KEY_FILE",
		PreserveWhitespace: true,
		Kind:               Text,
		Roles:              API | Worker,
		Secret:             true,
		Description:        "Store outside source control and logs.",
	},
	{
		Name:        "EVYDENCE_S3_USE_SSL",
		Kind:        Boolean,
		Roles:       API | Worker,
		Default:     "false",
		Description: "Use TLS for remote object storage.",
	},
}
