package main

import (
	"context"
	"os"

	"github.com/joho/godotenv"
	"github.com/nais/dependencytrack/pkg/client"
	log "github.com/sirupsen/logrus"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}
	adminPwd := os.Getenv("ADMIN_PWD")
	baseUrl := os.Getenv("BASE_URL")

	c := client.New(baseUrl, "admin", adminPwd)
	projects, err := c.GetProjects(context.Background())
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	for _, project := range projects {
		log.Infof("Deleting project %s\n", project.Name)
		if err := c.DeleteProject(ctx, project.Uuid); err != nil {
			log.Fatalf("Error deleting project %s: %s", project.Name, err)
		}
	}
	err = c.PortfolioRefresh(ctx)
	if err != nil {
		log.Fatalf("Error refreshing portfolio: %s", err)
	}
}
