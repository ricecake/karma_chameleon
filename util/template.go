package util

import (
	"encoding/json"
	"path/filepath"

	"github.com/flosch/pongo2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	inited  bool
	loader  *pongo2.LocalFilesystemLoader
	pageSet *pongo2.TemplateSet
)

type TemplateContext map[string]interface{}

func RenderHTMLTemplate(template string, context map[string]interface{}) (output []byte, renderErr error) {
	clientParams, renderErr := json.Marshal(context)

	if renderErr != nil {
		return
	}

	context["json_params"] = string(clientParams)

	return RenderTemplate("content", template, context)
}

func RenderEmailTemplate(template string, context map[string]interface{}) (subjectOutput, plainOutput, htmlOutput []byte, renderErr error) {
	subjectPath := filepath.Join(template, "subject")
	plainPath := filepath.Join(template, "plain")
	htmlPath := filepath.Join(template, "html")

	subjectOutput, renderErr = RenderTemplate("email", subjectPath, context)
	if renderErr != nil {
		return
	}
	plainOutput, renderErr = RenderTemplate("email", plainPath, context)
	if renderErr != nil {
		return
	}
	htmlOutput, renderErr = RenderTemplate("email", htmlPath, context)
	return
}

func RenderTemplate(style, template string, context map[string]interface{}) (output []byte, renderErr error) {
	templatePath := filepath.Join(viper.GetString("template.path"), style, template)

	ensureTemplates()

	templateBody, templateError := pageSet.FromCache(templatePath)
	if templateError != nil {
		renderErr = templateError
		return
	}

	output, renderErr = templateBody.ExecuteBytes(context)

	if renderErr != nil {
		log.Error(renderErr)
	}

	return
}

func ensureTemplates() {
	if !inited {
		loader = pongo2.MustNewLocalFileSystemLoader(viper.GetString("template.path"))
		pageSet = pongo2.NewSet("KarmaChameleon", loader)

		pageSet.Debug = viper.GetBool("template.debug")

		for index, element := range viper.GetStringMap("template.globals") {
			pageSet.Globals[index] = element
		}

		inited = true
	}
}
